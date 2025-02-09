def get_virus_total_score(sha256sum):
    import json
    import requests
    import os

    try:
        with open('config.json', 'r') as config_file:
            config = json.load(config_file)
            api_key = config.get('vt-api')
        if not os.path.exists('config.json'):
            raise FileNotFoundError("config.json file not found. Please create it with the necessary API key.")
        
        if not api_key:
            raise ValueError("API key not found in config file")

        url = f"https://www.virustotal.com/api/v3/search?query={sha256sum}"
        headers = {
            "x-apikey": api_key
        }

        try:
            response = requests.get(url, headers=headers)
        except requests.exceptions.ConnectionError:
            return "No internet connection"

        if response.status_code == 400:
            raise Exception("BadRequestError: The API request is invalid or malformed.")
        elif response.status_code == 401:
            raise Exception("AuthenticationRequiredError: The operation requires an authenticated user.")
        elif response.status_code == 403:
            raise Exception("ForbiddenError: You are not allowed to perform the requested operation.")
        elif response.status_code == 404:
            raise Exception("NotFoundError: The requested resource was not found.")
        elif response.status_code == 409:
            raise Exception("AlreadyExistsError: The resource already exists.")
        elif response.status_code == 424:
            raise Exception("FailedDependencyError: The request depended on another request and that request failed.")
        elif response.status_code == 429:
            raise Exception("QuotaExceededError: You have exceeded one of your quotas.")
        elif response.status_code == 503:
            raise Exception("TransientError: Transient server error. Retry might work.")
        elif response.status_code == 504:
            raise Exception("DeadlineExceededError: The operation took too long to complete.")
        elif response.status_code != 200:
            raise Exception(f"Error fetching data from VirusTotal: {response.status_code}")

        data = response.json()
        score = data['data']['attributes']['last_analysis_stats']

        return score

    except Exception as e:
        return str(e)
