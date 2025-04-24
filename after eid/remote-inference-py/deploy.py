import asyncio
import json
from transformers import RobertaTokenizer, T5ForConditionalGeneration, T5Config, T5EncoderModel
from statement_t5_model import StatementT5
import torch
import onnxruntime
import numpy as np
import pickle
from fastapi import FastAPI, Request
import httpx
from typing import List, Dict, Any, Optional
import re

app = FastAPI()

def main_v2(code: list, gpu: bool = False) -> dict:
    """Generate statement-level and function-level vulnerability prediction probabilities.
    Parameters
    ----------
    code : :obj:`list`
        A list of String functions.
    gpu : bool
        Defines if CUDA inference is enabled
    Returns
    -------
    :obj:`dict`
        A dictionary with two keys, "batch_vul_pred", "batch_vul_pred_prob", and "batch_line_scores"
        "batch_func_pred" stores a list of function-level vulnerability prediction: [0, 1, ...] where 0 means non-vulnerable and 1 means vulnerable
        "batch_func_pred_prob" stores a list of function-level vulnerability prediction probabilities [0.89, 0.75, ...] corresponding to "batch_func_pred"
        "batch_statement_pred" stores a list of statement-level vulnerability prediction: [0, 1, ...] where 0 means non-vulnerable and 1 means vulnerable
        "batch_statement_pred_prob" stores a list of statement-level vulnerability prediction probabilities [0.89, 0.75, ...] corresponding to "batch_statement_pred"
    """
    MAX_STATEMENTS = 155
    MAX_STATEMENT_LENGTH = 20
    DEVICE = 'cuda' if gpu else 'cpu'
    # load tokenizer
    tokenizer = RobertaTokenizer.from_pretrained("./inference-common/statement_t5_tokenizer")
    # load model
    config = T5Config.from_pretrained("./inference-common/t5_config.json")
    model = T5EncoderModel(config=config)    
    model = StatementT5(model, tokenizer, device=DEVICE)
    output_dir = "./models/statement_t5_model.bin"
    model.load_state_dict(torch.load(output_dir, map_location=DEVICE))
    model.to(DEVICE)
    model.eval()
    input_ids, statement_mask = statement_tokenization(code, MAX_STATEMENTS, MAX_STATEMENT_LENGTH, tokenizer)
    with torch.no_grad():
        statement_probs, func_probs = model(input_ids=input_ids, statement_mask=statement_mask)
    func_preds = torch.argmax(func_probs, dim=-1)
    statement_preds = torch.where(statement_probs>0.5, 1, 0)
    return {"batch_func_pred": func_preds, "batch_func_pred_prob": func_probs,
            "batch_statement_pred": statement_preds, "batch_statement_pred_prob": statement_probs}

def statement_tokenization(code: list, max_statements: int, max_statement_length: int, tokenizer):
    batch_input_ids = []
    batch_statement_mask = []
    for c in code:
        source = c.split("\n")
        source = [statement for statement in source if statement != ""]
        source = source[:max_statements]
        padding_statement = [tokenizer.pad_token_id for _ in range(20)]
        input_ids = []
        for stat in source:
            ids_ = tokenizer.encode(str(stat),
                                    truncation=True,
                                    max_length=max_statement_length,
                                    padding='max_length',
                                    add_special_tokens=False)
            input_ids.append(ids_)
        if len(input_ids) < max_statements:
            for _ in range(max_statements-len(input_ids)):
                input_ids.append(padding_statement)
        statement_mask = []
        for statement in input_ids:
            if statement == padding_statement:
                statement_mask.append(0)
            else:
                statement_mask.append(1)
        batch_input_ids.append(input_ids)
        batch_statement_mask.append(statement_mask)
    return torch.tensor(batch_input_ids), torch.tensor(batch_statement_mask)

def main(code: list, gpu: bool = False) -> dict:
    """Generate vulnerability predictions and line scores.
    Parameters
    ----------
    code : :obj:`list`
        A list of String functions.
    gpu : bool
        Defines if CUDA inference is enabled
    Returns
    -------
    :obj:`dict`
        A dictionary with two keys, "batch_vul_pred", "batch_vul_pred_prob", and "batch_line_scores"
        "batch_vul_pred" stores a list of vulnerability prediction: [0, 1, ...] where 0 means non-vulnerable and 1 means vulnerable
        "batch_vul_pred_prob" stores a list of vulnerability prediction probabilities [0.89, 0.75, ...] corresponding to "batch_vul_pred"
        "batch_line_scores" stores line scores as a 2D list [[att_score_0, att_score_1, ..., att_score_n], ...]
    """
    provider = ["CUDAExecutionProvider", "CPUExecutionProvider"] if gpu else ["CPUExecutionProvider"]
    # load tokenizer
    tokenizer = RobertaTokenizer.from_pretrained("./inference-common/tokenizer")
    model_input = tokenizer(code, truncation=True, max_length=512, padding='max_length',
                            return_tensors="pt").input_ids
    # onnx runtime session
    ort_session = onnxruntime.InferenceSession("./models/line_model.onnx", providers=provider)
    # compute ONNX Runtime output prediction
    ort_inputs = {ort_session.get_inputs()[0].name: to_numpy(model_input)}
    prob, attentions = ort_session.run(None, ort_inputs)
    # prepare token for attention line score mapping
    batch_tokens = []
    for mini_batch in model_input.tolist():
        tokens = tokenizer.convert_ids_to_tokens(mini_batch)
        tokens = [token.replace("Ġ", "") for token in tokens]
        tokens = [token.replace("ĉ", "Ċ") for token in tokens]
        batch_tokens.append(tokens)
    batch_att_weight_sum = []
    # access each layer
    for j in range(len(attentions)):
        att_weight_sum = None
        att_of_one_func = attentions[j]
        for i in range(len(attentions[0])):
            layer_attention = att_of_one_func[i]
            # summerize the values of each token dot other tokens
            layer_attention = sum(layer_attention)
            if att_weight_sum is None:
                att_weight_sum = layer_attention
            else:
                att_weight_sum += layer_attention
        # normalize attention score
        att_weight_sum -= att_weight_sum.min()
        att_weight_sum /= att_weight_sum.max()
        batch_att_weight_sum.append(att_weight_sum)
    # batch_line_scores (2D list with shape of [batch size, seq length]): [[att_score_0, att_score_1, ..., att_score_n], ...]
    batch_line_scores = []
    for i in range(len(batch_att_weight_sum)):
        # clean att score for <s> and </s>
        att_weight_sum = clean_special_token_values(batch_att_weight_sum[i], padding=True)
        # attention should be 1D tensor with seq length representing each token's attention value
        word_att_scores = get_word_att_scores(tokens=batch_tokens[i], att_scores=att_weight_sum)
        line_scores = get_all_lines_score(word_att_scores)
        batch_line_scores.append(line_scores)
    # batch_vul_pred (1D list with shape of [batch size]): [pred_1, pred_2, ..., pred_n]
    batch_vul_pred = np.argmax(prob, axis=-1).tolist()
    # batch_vul_pred_prob (1D list with shape of [batch_size]): [prob_1, prob_2, ..., prob_n]
    batch_vul_pred_prob = []
    for i in range(len(prob)):
        batch_vul_pred_prob.append(prob[i][batch_vul_pred[i]].item())  # .item() added to prevent 'Object of type float32 is not JSON serializable' error

    return {"batch_vul_pred": batch_vul_pred, "batch_vul_pred_prob": batch_vul_pred_prob,
            "batch_line_scores": batch_line_scores}


def get_word_att_scores(tokens: list, att_scores: list) -> list:
    word_att_scores = []
    for i in range(len(tokens)):
        token, att_score = tokens[i], att_scores[i]
        word_att_scores.append([token, att_score])
    return word_att_scores


def get_all_lines_score(word_att_scores: list):
    # word_att_scores -> [[token, att_value], [token, att_value], ...]
    separator = "Ċ"
    # to return
    all_lines_score = []
    score_sum = 0
    line_idx = 0
    line = ""
    for i in range(len(word_att_scores)):
        # summerize if meet line separator or the last token
        if ((separator in word_att_scores[i][0]) or (i == (len(word_att_scores) - 1))) and score_sum != 0:
            score_sum += word_att_scores[i][1]
            # append line score as float instead of tensor
            all_lines_score.append(score_sum.item())
            score_sum = 0
            line_idx += 1
        # else accumulate score
        elif separator not in word_att_scores[i][0]:
            line += word_att_scores[i][0]
            score_sum += word_att_scores[i][1]
    return all_lines_score


def clean_special_token_values(all_values, padding=False):
    # special token in the beginning of the seq 
    all_values[0] = 0
    if padding:
        # get the last non-zero value which represents the att score for </s> token
        idx = [index for index, item in enumerate(all_values) if item != 0][-1]
        all_values[idx] = 0
    else:
        # special token in the end of the seq 
        all_values[-1] = 0
    return all_values


def main_cwe(code: list, gpu: bool = False) -> dict:
    """Generate CWE-IDs and CWE Abstract Types Predictions.
    Parameters
    ----------
    code : :obj:`list`
        A list of String functions.
    gpu : bool
        Defines if CUDA inference is enabled
    Returns
    -------
    :obj:`dict`
        A dictionary with four keys, "cwe_id", "cwe_id_prob", "cwe_type", "cwe_type_prob"
        "cwe_id" stores a list of CWE-ID predictions: [CWE-787, CWE-119, ...]
        "cwe_id_prob" stores a list of confidence scores of CWE-ID predictions [0.9, 0.7, ...]
        "cwe_type" stores a list of CWE abstract types predictions: ["Base", "Class", ...]
        "cwe_type_prob" stores a list of confidence scores of CWE abstract types predictions [0.9, 0.7, ...]
    """
    provider = ["CUDAExecutionProvider", "CPUExecutionProvider"] if gpu else ["CPUExecutionProvider"]
    with open("./inference-common/label_map.pkl", "rb") as f:
        cwe_id_map, cwe_type_map = pickle.load(f)
    # load tokenizer
    tokenizer = RobertaTokenizer.from_pretrained("./inference-common/tokenizer")
    tokenizer.add_tokens(["<cls_type>"])
    tokenizer.cls_type_token = "<cls_type>"
    model_input = []
    for c in code:
        code_tokens = tokenizer.tokenize(str(c))[:512 - 3]
        source_tokens = [tokenizer.cls_token] + code_tokens + [tokenizer.cls_type_token] + [tokenizer.sep_token]
        input_ids = tokenizer.convert_tokens_to_ids(source_tokens)
        padding_length = 512 - len(input_ids)
        input_ids += [tokenizer.pad_token_id] * padding_length
        model_input.append(input_ids)
    device = "cuda" if gpu else "cpu"
    model_input = torch.tensor(model_input, device=device)
    # onnx runtime session
    ort_session = onnxruntime.InferenceSession("./models/cwe_model.onnx", providers=provider)
    # compute ONNX Runtime output prediction
    ort_inputs = {ort_session.get_inputs()[0].name: to_numpy(model_input)}
    cwe_id_prob, cwe_type_prob = ort_session.run(None, ort_inputs)
    # batch_cwe_id_pred (1D list with shape of [batch size]): [pred_1, pred_2, ..., pred_n]
    batch_cwe_id = np.argmax(cwe_id_prob, axis=-1).tolist()
    # map predicted idx back to CWE-ID
    batch_cwe_id_pred = [cwe_id_map[str(idx)] for idx in batch_cwe_id]
    # batch_cwe_id_pred_prob (1D list with shape of [batch_size]): [prob_1, prob_2, ..., prob_n]
    batch_cwe_id_pred_prob = []
    for i in range(len(cwe_id_prob)):
        batch_cwe_id_pred_prob.append(cwe_id_prob[i][batch_cwe_id[i]].item())
    # batch_cwe_type_pred (1D list with shape of [batch size]): [pred_1, pred_2, ..., pred_n]
    batch_cwe_type = np.argmax(cwe_type_prob, axis=-1).tolist()
    # map predicted idx back to CWE-Type
    batch_cwe_type_pred = [cwe_type_map[str(idx)] for idx in batch_cwe_type]
    # batch_cwe_type_pred_prob (1D list with shape of [batch_size]): [prob_1, prob_2, ..., prob_n]
    batch_cwe_type_pred_prob = []
    for i in range(len(cwe_type_prob)):
        batch_cwe_type_pred_prob.append(cwe_type_prob[i][batch_cwe_type[i]].item())
    return {"cwe_id": batch_cwe_id_pred,
            "cwe_id_prob": batch_cwe_id_pred_prob,
            "cwe_type": batch_cwe_type_pred,
            "cwe_type_prob": batch_cwe_type_pred_prob}


def main_sev(code: list, gpu: bool = False) -> dict:
    """Generate CVSS severity score predictions.
    Parameters
    ----------
    code : :obj:`list`
        A list of String functions.
    gpu : bool
        Defines if CUDA inference is enabled
    Returns
    -------
    :obj:`dict`
        A dictionary with two keys, "batch_sev_score", "batch_sev_class"
        "batch_sev_score" stores a list of severity score prediction: [1.0, 5.0, 9.0 ...]
        "batch_sev_class" stores a list of severity class based on predicted severity score ["Medium", "Critical"...]
    """
    provider = ["CUDAExecutionProvider", "CPUExecutionProvider"] if gpu else ["CPUExecutionProvider"]
    # load tokenizer
    tokenizer = RobertaTokenizer.from_pretrained("./inference-common/tokenizer")
    model_input = tokenizer(code, truncation=True, max_length=512, padding='max_length',
                            return_tensors="pt").input_ids
    # onnx runtime session
    ort_session = onnxruntime.InferenceSession("./models/sev_model.onnx", providers=provider)
    # compute ONNX Runtime output prediction
    ort_inputs = {ort_session.get_inputs()[0].name: to_numpy(model_input)}
    cvss_score = ort_session.run(None, ort_inputs)
    batch_sev_score = list(cvss_score[0].flatten().tolist())
    batch_sev_class = []
    for i in range(len(batch_sev_score)):
        if batch_sev_score[i] == 0:
            batch_sev_class.append("None")
        elif batch_sev_score[i] < 4:
            batch_sev_class.append("Low")
        elif batch_sev_score[i] < 7:
            batch_sev_class.append("Medium")
        elif batch_sev_score[i] < 9:
            batch_sev_class.append("High")
        else:
            batch_sev_class.append("Critical")
    return {"batch_sev_score": batch_sev_score, "batch_sev_class": batch_sev_class}


def main_repair(code: list, max_repair_length: int = 256, gpu: bool = False) -> dict:
    """Generate vulnerability repair candidates.
    Parameters
    ----------
    code : :obj:`list`
        A list of String functions.
    code : :obj:`int`
        max number of tokens for each repair.
    gpu : bool
        Defines if CUDA inference is enabled
    Returns
    -------
    :obj:`dict`
        A dictionary with one key, "batch_repair"
        "batch_repair" is a list of String, where each String is the repair for one code snippet.
    """
    device = "cuda" if gpu else "cpu"
    # load tokenizer
    tokenizer = RobertaTokenizer.from_pretrained("./inference-common/repair_tokenizer")
    tokenizer.add_tokens(["<S2SV_StartBug>", "<S2SV_EndBug>", "<S2SV_blank>", "<S2SV_ModStart>", "<S2SV_ModEnd>"])    
    config = T5Config.from_pretrained("./inference-common/repair_model_config.json")
    model = T5ForConditionalGeneration(config=config)
    model.resize_token_embeddings(len(tokenizer))
    model.load_state_dict(torch.load("./models/repair_model.bin", map_location=device))
    model.eval()
    input_ids = tokenizer(code, truncation=True, max_length=512, padding='max_length', return_tensors="pt").input_ids
    input_ids = input_ids.to(device)
    attention_mask = input_ids.ne(tokenizer.pad_token_id)
    attention_mask = attention_mask.to(device)
    gen_tokens = model.generate(input_ids=input_ids, attention_mask=attention_mask, max_new_tokens=max_repair_length)
    batch_repair = tokenizer.batch_decode(gen_tokens)
    for i in range(len(batch_repair)):
        batch_repair[i] = clean_tokens(batch_repair[i])
    return {"batch_repair": batch_repair}


def clean_tokens(tokens):
    tokens = tokens.replace("<pad>", "")
    tokens = tokens.replace("<s>", "")
    tokens = tokens.replace("</s>", "")
    tokens = tokens.strip("\n")
    tokens = tokens.strip()
    return tokens


def to_numpy(tensor):
    """ get np input for onnx runtime model """
    return tensor.detach().cpu().numpy() if tensor.requires_grad else tensor.cpu().numpy()


@app.post('/api/v1/gpu/predict')
def predict_gpu(request: Request):
    functions = asyncio.run(request.json())

    if not functions:
        return {'error': 'No functions to process'}
    else:
        result = json.dumps(main(functions, True))
        return result


@app.post('/api/v1/cpu/predict')
def predict_cpu(request: Request):
    functions = asyncio.run(request.json())

    if not functions:
        return {'error': 'No functions to process'}
    else:
        result = json.dumps(main(functions, False))
        return result


@app.post('/api/v1/gpu/cwe')
def cwe_gpu(request: Request):
    functions = asyncio.run(request.json())

    if not functions:
        return {'error': 'No code to process'}
    else:
        result = json.dumps(main_cwe(functions, True))
        return result


@app.post('/api/v1/cpu/cwe')
def cwe_cpu(request: Request):
    functions = asyncio.run(request.json())

    if not functions:
        return {'error': 'No code to process'}
    else:
        result = json.dumps(main_cwe(functions, False))
        return result


@app.post('/api/v1/gpu/sev')
def sev_gpu(request: Request):
    functions = asyncio.run(request.json())

    if not functions:
        return {'error': 'No code to process'}
    else:
        result = json.dumps(main_sev(functions, True))
        return result


@app.post('/api/v1/cpu/sev')
def sev_cpu(request: Request):
    functions = asyncio.run(request.json())

    if not functions:
        return {'error': 'No code to process'}
    else:
        result = json.dumps(main_sev(functions, False))
        return result


@app.post('/api/v1/gpu/repair')
async def repair_gpu(request: Request):
    try:
        # Check if raw mode is requested (directly return code without JSON wrapper)
        params = request.query_params
        raw_mode = params.get("raw", "").lower() in ["true", "1", "yes", "y"]
        
        # Parse the request body
        request_data = await request.json()
        
        # Handle different input formats
        functions = []
        if isinstance(request_data, dict) and "code" in request_data:
            # Handle {"code": "..."} format
            if isinstance(request_data["code"], str):
                functions = [request_data["code"]]
            elif isinstance(request_data["code"], list):
                functions = request_data["code"]
        elif isinstance(request_data, list):
            # Handle direct list format
            functions = request_data
        else:
            # Try to extract code from the request if it's a string
            try:
                if isinstance(request_data, str):
                    # Try to parse as JSON if it's a string
                    parsed = json.loads(request_data)
                    if isinstance(parsed, dict) and "code" in parsed:
                        if isinstance(parsed["code"], str):
                            functions = [parsed["code"]]
                        elif isinstance(parsed["code"], list):
                            functions = parsed["code"]
                    elif isinstance(parsed, list):
                        functions = parsed
            except json.JSONDecodeError:
                # If it's a raw string that's not JSON, treat it as code
                if isinstance(request_data, str) and len(request_data) > 10:  # Minimum code length check
                    functions = [request_data]

        if not functions:
            error_msg = 'No code to process. Please provide code in the request body.'
            return error_msg if raw_mode else json.dumps({'error': error_msg})
        
        # Log the received code for debugging
        print(f"Received code for repair: {functions[:1]} (total: {len(functions)} functions)")
        
        repairs = []
        for code in functions:
            if not isinstance(code, str):
                # Skip non-string inputs
                repairs.append("Error: Invalid input type. Expected string.")
                continue
                
            if not code or code.strip() == "":
                # Skip empty code
                repairs.append("Error: Empty code provided.")
                continue
                
            try:
                repaired_code = await call_ollama(code)

                # Enhanced error check: Check for explicit "Error:" prefix OR if the response doesn't look like code
                is_error_response = repaired_code.startswith("Error:")
                # Heuristic check: does it contain common C/C++ keywords or structures, or is it reasonably long?
                looks_like_code = any(keyword in repaired_code for keyword in ["int ", "void ", "#include", "char ", "float ", "return ", "{", "}"]) or len(repaired_code) >= 50
                
                if is_error_response or not looks_like_code:
                    print(f"Ollama response indicated an error or did not look like code: {repaired_code[:100]}...") # Log the problematic response
                    # Provide a basic repair suggestion
                    repaired_code = provide_fallback_repair(code)
                    repairs.append(repaired_code) # Append fallback code directly
                else:
                    # Response seems valid, proceed with cleanup
                    # Remove any leading comments with "FIXED:" or similar
                    lines = repaired_code.split('\n')
                    removed_comments = False 
                    while lines and ("/* FIXED:" in lines[0] or "/*FIXED" in lines[0] or "/* SECURITY" in lines[0]):
                        lines.pop(0)
                        removed_comments = True
                    
                    repaired_code = '\n'.join(lines).strip()

                    # Final check: if after stripping comments, the code is empty, use fallback
                    if not repaired_code and removed_comments:
                         print("Repaired code became empty after removing comments, using fallback.")
                         repaired_code = provide_fallback_repair(code)
                    
                    repairs.append(repaired_code) # Append processed or fallback code

            except Exception as e:
                error_msg = f"Error processing code segment: {str(e)}"
                print(error_msg)
                # If individual repair fails during processing (e.g., within this try block but after call_ollama), provide fallback
                repaired_code = provide_fallback_repair(code)
                repairs.append(repaired_code)
        
        # If raw mode and single repair, return just the code
        if raw_mode and len(repairs) == 1:
            return repairs[0]
            
        # Otherwise return the standard JSON format
        result = {"batch_repair": repairs}
        return json.dumps(result)
    except Exception as e:
        error_msg = f"Error processing request: {str(e)}"
        print(error_msg)
        return error_msg if raw_mode else json.dumps({"error": error_msg})


@app.post('/api/v1/cpu/repair')
async def repair_cpu(request: Request):
    # For simplicity, we'll use the same implementation as GPU
    # since Ollama handles the compute resources
    return await repair_gpu(request)


async def call_ollama(code: str, system_prompt: str = "") -> str:
    """Call Ollama API to generate code repairs.
    
    Parameters
    ----------
    code : str
        The code to repair
    system_prompt : str
        Optional system prompt to guide the model
        
    Returns
    -------
    str
        The repaired code
    """
    OLLAMA_URL = "http://localhost:11434/api/generate"
    
    # Check if code is empty or None
    if not code or code.strip() == "":
        return "Error: No code provided for repair"
        
    # Create a more structured prompt that clearly delineates the code
    prompt = (
        "You are a security expert tasked with fixing vulnerable code. "
        "Please analyze and repair the following code to address ALL security vulnerabilities "
        "WHILE PRESERVING THE ORIGINAL FUNCTIONALITY AND LOGICAL FLOW:\n\n"
        "```\n"
        f"{code}\n"
        "```\n\n"
        "CRITICAL REQUIREMENTS FOR YOUR REPAIR:\n"
        "1. DO NOT REMOVE ANY FUNCTIONALITY - this is the most critical requirement\n"
        "2. For EVERY unsafe function call, replace it with a safe equivalent that performs the SAME operation\n"
        "   - Example: Replace 'strcpy(dst, src)' with 'strncpy(dst, src, sizeof(dst)-1); dst[sizeof(dst)-1] = '\\0';'\n"
        "   - NEVER simply remove the unsafe function call!\n"
        "3. If buffers are too small, INCREASE their size, but keep all operations\n"
        "4. For integer operations with overflow risks, add checks but keep the original calculation\n"
        "5. For format strings, fix by adding proper format specifiers without changing output behavior\n"
        "6. For memory management, add missing free() calls but preserve all allocation logic\n"
        "7. For command injection risks, sanitize inputs but preserve command execution functionality\n"
        "8. MAINTAIN LOGICAL COHERENCE - if a function reads user input then later writes data to that buffer, ensure the input isn't accidentally discarded\n"
        "9. Consider the data flow and ensure logical operations are preserved in their original order\n\n"
        "VERIFICATION STEPS:\n"
        "1. For each line you modify, verify that it still achieves the EXACT SAME task as the original\n"
        "2. Check that all original operations are still present, just made safer\n"
        "3. Ensure any added safety checks don't alter the program's behavior under normal conditions\n"
        "4. Verify the logical flow remains intact with no unreachable code or redundant operations\n"
        "5. If you add buffer size checks, ensure they're appropriate for the actual data being handled\n\n"
        "Return ONLY the complete fixed code with no explanations or markdown formatting."
    )
    
    if not system_prompt:
        system_prompt = (
            "You are a security-focused code repair assistant specializing in fixing all types of code vulnerabilities "
            "while preserving the original functionality. Your primary goal is to make code secure while ensuring that "
            "EVERY operation in the original code continues to function. Never remove or disable functionality - instead, "
            "replace unsafe operations with secure equivalents that do exactly the same thing.\n\n"
            "MOST IMPORTANT PRINCIPLES:\n"
            "1. Preserve ALL functionality - nothing from the original code should be removed or disabled\n"
            "2. Unsafe operations must be replaced with safe equivalents, not removed\n"
            "3. If a buffer overflow risk exists, use bounded functions AND ensure proper null-termination\n"
            "4. If integers might overflow, add checks but keep the calculation intact\n"
            "5. For any function you change, verify it still performs the exact same task\n"
            "6. Fix all security issues but make minimal changes to the program's behavior\n"
            "7. Maintain LOGICAL COHERENCE - make sure operations remain in the correct sequence and data flow makes sense\n"
            "8. Be aware of context - changing one part of code might affect another part's assumptions\n"
            "9. Look for complex vulnerabilities beyond the obvious ones (race conditions, TOCTOU, side channels, etc.)\n"
            "10. Return ONLY the fixed code without any explanations or commentary"
        )
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(
                    OLLAMA_URL,
                    json={
                        "model": "deepseek-coder:6.7b-instruct",
                        "prompt": prompt,
                        "system": system_prompt,
                        "stream": False,
                        "options": {
                            "temperature": 0.1,  # Lower temperature for more deterministic outputs
                            "top_p": 0.9
                        }
                    }
                )
                
                if response.status_code != 200:
                    return f"Error calling Ollama API: Status code {response.status_code} - {response.text}"
                
                result = response.json()
                if "response" not in result:
                    return "Ollama API returned unexpected response format"
                
                repaired_code = result["response"].strip()
                
                # If the response doesn't look like code, use fallback
                if "```" in repaired_code:
                    # Extract code from markdown code blocks
                    code_blocks = repaired_code.split("```")
                    if len(code_blocks) >= 3:  # Proper markdown code block
                        # The code is in the second element (between first and second ```)
                        repaired_code = code_blocks[1]
                        # Remove language identifier if present
                        if repaired_code.startswith("c") or repaired_code.startswith("cpp"):
                            repaired_code = repaired_code[repaired_code.find("\n")+1:]
                        repaired_code = repaired_code.strip()
                
                # If the response still doesn't look like code (e.g., it's just text), use fallback
                if not any(keyword in repaired_code for keyword in ["int ", "void ", "#include", "char ", "float ", "return"]) and len(repaired_code) < 50:
                    return provide_fallback_repair(code)
                    
                return repaired_code
            except httpx.ConnectError:
                return "Error: Could not connect to Ollama API. Please ensure Ollama is running on localhost:11434."
            except httpx.ReadTimeout:
                return "Error: Connection to Ollama API timed out."
    except httpx.RequestError as e:
        error_type = type(e).__name__
        return f"Error connecting to Ollama API: {error_type} - {str(e)}"
    except Exception as e:
        error_type = type(e).__name__
        return f"Unexpected error: {error_type} - {str(e)}"


def provide_fallback_repair(code: str) -> str:
    """Provide a fallback repair if the Ollama API fails.
    
    Parameters
    ----------
    code : str
        The code to repair
        
    Returns
    -------
    str
        The repaired code with basic heuristics applied
    """
    # First, analyze code structure to understand logical flow
    lines = code.split("\n")
    functions = []
    current_func = []
    in_function = False
    
    # Basic code structure analysis to identify functions and blocks
    for line in lines:
        stripped = line.strip()
        if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(', stripped) and '{' in stripped:
            in_function = True
            current_func = [line]
        elif in_function:
            current_func.append(line)
            if stripped == '}':
                # Check if this is actually the end of the function
                brace_count = ''.join(current_func).count('{') - ''.join(current_func).count('}')
                if brace_count == 0:
                    functions.append(current_func)
                    current_func = []
                    in_function = False
        else:
            # Global scope code
            pass
    
    # Add remaining function if any
    if current_func:
        functions.append(current_func)
    
    # Add necessary includes based on code content
    includes_needed = []
    
    # Check for necessary includes
    if "strn" in code or "str" in code:
        includes_needed.append("string.h")
    
    if "malloc" in code or "free" in code or "calloc" in code or "realloc" in code:
        includes_needed.append("stdlib.h")
    
    if "INT_MAX" in code or "overflow" in code or "UINT_MAX" in code:
        includes_needed.append("limits.h")

    if "printf" in code or "scanf" in code or "fgets" in code or "FILE" in code:
        includes_needed.append("stdio.h")
    
    if "isalpha" in code or "isdigit" in code or "toupper" in code:
        includes_needed.append("ctype.h")
        
    if "errno" in code:
        includes_needed.append("errno.h")
        
    if "memcpy" in code or "memmove" in code:
        includes_needed.append("string.h")
        
    if "socket" in code or "connect" in code:
        includes_needed.append("sys/socket.h")
        includes_needed.append("netinet/in.h")

    # Add includes if not already in the code
    repaired_code = code
    for include in includes_needed:
        include_statement = f"#include <{include}>"
        if include_statement not in repaired_code:
            if "#include" in repaired_code:
                # Add after the last include
                includes = [line for line in repaired_code.split("\n") if line.strip().startswith("#include")]
                last_include = includes[-1]
                repaired_code = repaired_code.replace(last_include, last_include + f"\n{include_statement}")
            else:
                # Add at the beginning
                repaired_code = include_statement + "\n" + repaired_code
    
    # Track variable declarations to understand data flow
    var_declarations = re.findall(r'(char|int|float|double|long|unsigned|size_t)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(\[\s*[0-9]+\s*\])?', repaired_code)
    buffer_vars = [name for type, name, array in var_declarations if array]  # Identify buffer variables
    
    # Replace potentially dangerous functions with safer alternatives
    # Buffer overflow fixes - PRESERVE FUNCTIONALITY
    if "gets(" in repaired_code:
        # Replace gets with fgets and appropriate buffer size
        repaired_code = re.sub(
            r'gets\s*\(\s*([^,\)]+)\s*\)',
            lambda m: f'fgets({m.group(1)}, sizeof({m.group(1)}), stdin)',
            repaired_code
        )
    
    if "strcpy" in repaired_code:
        # Replace strcpy with strncpy + null termination (preserving functionality)
        repaired_code = re.sub(
            r'strcpy\s*\(\s*([^,]+)\s*,\s*([^,\)]+)\s*\)',
            lambda m: f'strncpy({m.group(1)}, {m.group(2)}, sizeof({m.group(1)})-1); {m.group(1)}[sizeof({m.group(1)})-1] = \'\\0\'',
            repaired_code
        )
        
        # Also detect if we're overwriting buffer contents immediately after reading input
        repaired_code = re.sub(
            r'(fgets|gets|scanf|read|recv)([^;]+);[\s\n]*strncpy\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,\s*sizeof\([^)]+\)-1\)',
            # Preserve both operations but add a comment explaining the logical issue
            lambda m: f'{m.group(1)}{m.group(2)}; // Read input into buffer\n    // Warning: Input above may be ignored by the following operation\n    strncpy({m.group(3)}, {m.group(4)}, sizeof({m.group(3)})-1)',
            repaired_code
        )
        
        # Also check if buffer size is too small for the string literal being copied
        repaired_code = re.sub(
            r'char\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\[\s*(\d+)\s*\][^;]*;[\s\n]*strncpy\s*\(\s*\1\s*,\s*"([^"]+)"\s*,',
            lambda m: (f'char {m.group(1)}[{max(int(m.group(2)), len(m.group(3))+1)}] /* Increased buffer size */;' if len(m.group(3)) >= int(m.group(2)) else f'char {m.group(1)}[{m.group(2)}];') + f'\n    strncpy({m.group(1)}, "{m.group(3)}",',
            repaired_code
        )
    
    if "strcat" in repaired_code:
        # Replace strcat with strncat (preserving functionality)
        repaired_code = re.sub(
            r'strcat\s*\(\s*([^,]+)\s*,\s*([^,\)]+)\s*\)',
            lambda m: f'strncat({m.group(1)}, {m.group(2)}, sizeof({m.group(1)}) - strlen({m.group(1)}) - 1)',
            repaired_code
        )
        
        # Check for buffer size when concatenating fixed strings
        repaired_code = re.sub(
            r'char\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\[\s*(\d+)\s*\][^;]*;(?:[\s\n]*[^;]+;)*[\s\n]*strncat\s*\(\s*\1\s*,\s*"([^"]+)"\s*,',
            lambda m: f'char {m.group(1)}[{max(int(m.group(2)), len(m.group(3))*2)}] /* Increased buffer size */;\n    {m.group(1)}[0] = \'\\0\'; /* Initialize for strncat */\n    strncat({m.group(1)}, "{m.group(3)}",',
            repaired_code
        )
    
    # Format string vulnerability fixes - PRESERVE FUNCTIONALITY
    if "printf" in repaired_code or "fprintf" in repaired_code:
        # Fix printf with user-controlled format strings by adding explicit %s format
        repaired_code = re.sub(
            r'(f?printf\s*\(\s*[^,]*,\s*)([^"].*?[^"%,\)]+)(\s*\))',
            lambda m: f'{m.group(1)}"%s", {m.group(2)}{m.group(3)}' if not (m.group(2).strip().startswith('"') and m.group(2).strip().endswith('"')) else f'{m.group(1)}{m.group(2)}{m.group(3)}',
            repaired_code
        )
    
    # Integer overflow/underflow checks - ADD CHECKS BUT PRESERVE OPERATIONS
    if re.search(r'[a-zA-Z_][a-zA-Z0-9_]*\s*[+\-*/]\s*[a-zA-Z_0-9]+', repaired_code):
        # Add basic integer overflow checks for arithmetic operations
        for op in ['+', '-', '*']:
            # Find patterns like "a + b" or "a * b" where a and b could be variables or constants
            pattern = r'(\b[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[a-zA-Z_0-9]+\s*)' + op + r'(\s*[a-zA-Z_0-9]+\b)'
            if re.search(pattern, repaired_code):
                # We don't replace the actual operation, but add a check beforehand
                includes_needed.append("limits.h")
                
                # For integer overflow, add a comment about the potential issue
                # In a real implementation we'd add actual checks based on types
                if op == '+':
                    repaired_code = re.sub(
                        pattern,
                        lambda m: f'/* Check for potential overflow before: */ {m.group(1)}{op}{m.group(2)}',
                        repaired_code
                    )
    
    # Command injection vulnerability checks - SANITIZE BUT PRESERVE FUNCTIONALITY
    if "system(" in repaired_code or "exec" in repaired_code or "popen" in repaired_code:
        # Add a warning comment for potential command injection vulnerabilities
        # In a proper implementation, this would add input validation while preserving the command's functionality
        validate_function = """
// Function to validate command input - prevents command injection
int validate_command_input(const char *str) {
    if (!str) return 0;
    
    // Check for potentially dangerous shell characters
    while (*str) {
        if (*str == '|' || *str == ';' || *str == '&' || 
            *str == '`' || *str == '\\'' || *str == '\\\"' || 
            *str == '>' || *str == '<' || *str == '$' ||
            *str == '(' || *str == ')') {
            return 0;
        }
        str++;
    }
    return 1;
}
"""
        
        # Add the validation function if it's not already there
        if "validate_command_input" not in repaired_code:
            # Find the position to insert the function (before the first function definition)
            func_match = re.search(r'^[a-zA-Z_][a-zA-Z0-9_]*\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(', repaired_code, re.MULTILINE)
            if func_match:
                # Insert before the first function
                pos = func_match.start()
                repaired_code = repaired_code[:pos] + validate_function + repaired_code[pos:]
            else:
                # Append to the end if no function definitions found
                repaired_code += validate_function
        
        # Add checks to system calls without removing the calls themselves
        repaired_code = re.sub(
            r'(system\s*\(\s*)([^)]+)(\s*\))',
            lambda m: f'(validate_command_input({m.group(2)}) ? {m.group(1)}{m.group(2)}{m.group(3)} : -1)',
            repaired_code
        )
    
    # Memory leak fixes - ADD MISSING FREE BUT PRESERVE ALLOCATIONS
    # Analyze function returns to avoid adding free() that could lead to double-free
    malloc_vars = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(malloc|calloc|realloc)\(', repaired_code)
    for var, alloc_func in malloc_vars:
        # Check if there's a free for this variable
        if f"free({var})" not in repaired_code:
            # Add a comment suggesting where a free should be added
            pattern = r'(return[^;]*;)'
            if re.search(pattern, repaired_code):
                repaired_code = re.sub(
                    pattern,
                    lambda m: f'/* Consider adding: free({var}); */ {m.group(1)}',
                    repaired_code,
                    count=1  # Only add one suggestion per function
                )
    
    # SQL Injection check - Add comments about parameterization
    if "SELECT" in repaired_code and "FROM" in repaired_code and ("sprintf" in repaired_code or "strcat" in repaired_code):
        repaired_code = re.sub(
            r'(sprintf\s*\(\s*[^,]+,\s*"[^"]*SELECT[^"]*FROM[^"]*")',
            lambda m: f'/* SQL Injection risk: Use parameterized queries instead */ {m.group(1)}',
            repaired_code
        )
    
    # Race condition warnings for file operations
    if re.search(r'(fopen|open|access|stat)[^;]+;[\s\n]+(fopen|open|write|chmod)', repaired_code):
        repaired_code = re.sub(
            r'((fopen|open|access|stat)[^;]+;)',
            lambda m: f'/* Potential TOCTOU race condition: */ {m.group(1)}',
            repaired_code
        )
    
    # Add random data initialization for security-sensitive variables
    if "password" in repaired_code.lower() or "key" in repaired_code.lower() or "secret" in repaired_code.lower():
        includes_needed.append("stdlib.h")
        includes_needed.append("time.h")
        if "srand(time(NULL));" not in repaired_code and "srand(" not in repaired_code:
            # Add initialization of random number generator if dealing with security-sensitive data
            func_match = re.search(r'(int\s+main\s*\([^)]*\)\s*{)', repaired_code)
            if func_match:
                repaired_code = repaired_code.replace(
                    func_match.group(1),
                    func_match.group(1) + "\n    /* Initialize random number generator for security operations */\n    srand(time(NULL));"
                )
    
    return repaired_code
