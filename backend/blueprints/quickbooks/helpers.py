import logging, requests, json
from extensions import supabase
from datetime import datetime




def get_company_info(user_id):
    """
    Fetches the QuickBooks company info for the specified user_id.
    Automatically refreshes if tokens are expired.
    """
    try:
        tokens = get_quickbooks_tokens(user_id)
        access_token = tokens.get('access_token')
        realm_id = tokens.get('realm_id')
        expiry = tokens.get('token_expiry')

        if not access_token:
            raise Exception("No access token found. QuickBooks disconnected.")

        # Check for expiry
        if expiry and datetime.utcnow() > datetime.fromisoformat(expiry):
            logging.info("Access token expired. Refreshing...")
            refresh_access_token(user_id)
            tokens = get_quickbooks_tokens(user_id)
            access_token = tokens.get('access_token')
            realm_id = tokens.get('realm_id')

        # Make request to QBO
        headers = {
            'Authorization': f"Bearer {access_token}",
            'Accept': 'application/json'
        }
        api_url = f"{QUICKBOOKS_API_BASE_URL}{realm_id}/companyinfo/{realm_id}"
        response = requests.get(api_url, headers=headers)

        if response.status_code == 401:
            logging.info("Got 401 fetching company info. Trying refresh again...")
            refresh_access_token(user_id)
            tokens = get_quickbooks_tokens(user_id)
            access_token = tokens.get('access_token')
            headers['Authorization'] = f"Bearer {access_token}"
            response = requests.get(api_url, headers=headers)

        if response.status_code == 200:
            return response.json().get("CompanyInfo", {})
        else:
            logging.error(f"QuickBooks API Error: {response.status_code} - {response.text}")
            raise Exception(f"Failed to fetch company info: {response.status_code} {response.text}")
    except Exception as e:
        logging.error(f"Error in get_company_info: {e}")
        raise



#--------------- Fetch Report Def -------------------#

def fetch_report(
    user_id: str,
    report_type: str,
    start_date: str = None,
    end_date: str = None
) -> dict:
    """
    Fetches a financial report from QuickBooks for the specified user_id.
    This function:
      1) Retrieves the user’s QBO tokens from Supabase,
      2) Checks for expiry, refreshes if needed,
      3) Calls the QuickBooks /reports endpoint,
      4) Returns the JSON response or raises an Exception.
    """
    # 1) Retrieve tokens from DB
    tokens = get_quickbooks_tokens(user_id)
    access_token = tokens.get("access_token")
    realm_id     = tokens.get("realm_id")
    expiry_str   = tokens.get("token_expiry")

    if not access_token or not realm_id:
        raise Exception("Missing QuickBooks tokens or realm_id for this user.")

    # 2) Check if expired
    if expiry_str:
        expiry_dt = datetime.fromisoformat(expiry_str)
        if datetime.utcnow() > expiry_dt:
            logging.info("Access token expired; refreshing tokens...")
            refresh_access_token(user_id)
            # Now refetch the updated tokens
            tokens = get_quickbooks_tokens(user_id)
            access_token = tokens["access_token"]
            realm_id     = tokens["realm_id"]

    # 3) Make the request to QuickBooks
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }
    base_url = f"https://quickbooks.api.intuit.com/v3/company/{realm_id}/reports/{report_type}"

    params = {}
    if start_date:
        params["start_date"] = start_date
    if end_date:
        params["end_date"] = end_date

    response = requests.get(base_url, headers=headers, params=params)

    # 4) Handle possible 401 mid-request (token invalid again)
    if response.status_code == 401:
        logging.info("Token might have expired mid-request. Attempting second refresh...")
        refresh_access_token(user_id)
        tokens = get_quickbooks_tokens(user_id)
        access_token = tokens["access_token"]
        headers["Authorization"] = f"Bearer {access_token}"
        response = requests.get(base_url, headers=headers, params=params)

    # 5) Final check
    if response.status_code == 200:
        return response.json()
    else:
        logging.error(f"Error fetching {report_type} report: {response.text}")
        raise Exception(f"Failed to fetch {report_type} report: {response.status_code} {response.text}")



#--------------- Fetch Transactions Def -------------------#

def fetch_transactions(user_id: str, qb_params: dict) -> dict:
    """
    Fetches the TransactionList report from QuickBooks using a dynamic set of query parameters,
    then applies local filtering for parameters that require reference IDs (e.g. vendor, customer).
    
    The function:
      1. Retrieves QuickBooks tokens (and refreshes them if expired).
      2. Separates out parameters that QuickBooks expects as IDs (e.g. vendor) so that free‑form text isn’t sent.
      3. Calls the TransactionList endpoint.
      4. Processes the returned JSON—handling grouped rows and ignoring summary rows.
      5. Applies local filtering based on the removed parameters.
    
    :param user_id: The QuickBooks-connected user ID.
    :param qb_params: Dictionary of query parameters from the request.
    :return: A dictionary with a "transactions" key containing the filtered list.
    """
    # 1) Retrieve tokens from Supabase.
    tokens = get_quickbooks_tokens(user_id)
    access_token = tokens.get("access_token")
    realm_id = tokens.get("realm_id")
    expiry_str = tokens.get("token_expiry")
    
    if not access_token or not realm_id:
        raise Exception("Missing QuickBooks tokens or realm_id for this user.")
    
    # 2) Refresh token if expired.
    if expiry_str:
        expiry_dt = datetime.fromisoformat(expiry_str)
        if datetime.utcnow() > expiry_dt:
            logging.info("Access token expired; refreshing tokens...")
            refresh_access_token(user_id)
            tokens = get_quickbooks_tokens(user_id)
            access_token = tokens.get("access_token")
            realm_id = tokens.get("realm_id")
    
    # 3) Separate out filters that require local handling.
    # These keys (like vendor, customer, name, department, memo) expect reference IDs in QB,
    # so remove them from qb_params and store them for local filtering.
    local_filter_keys = ["vendor", "customer", "name", "department", "memo"]
    local_filters = {}
    for key in local_filter_keys:
        if key in qb_params:
            local_filters[key] = qb_params.pop(key)
    
    # 4) Build the API request to QuickBooks.
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }
    base_url = f"https://quickbooks.api.intuit.com/v3/company/{realm_id}/reports/TransactionList"
    response = requests.get(base_url, headers=headers, params=qb_params)
    
    # 5) Handle potential token expiry mid-request.
    if response.status_code == 401:
        logging.info("Token might have expired mid-request. Attempting second refresh...")
        refresh_access_token(user_id)
        tokens = get_quickbooks_tokens(user_id)
        access_token = tokens.get("access_token")
        headers["Authorization"] = f"Bearer {access_token}"
        response = requests.get(base_url, headers=headers, params=qb_params)
    
    if response.status_code != 200:
        logging.error(f"Error fetching TransactionList report: {response.text}")
        raise Exception(f"Failed to fetch TransactionList report: {response.status_code} {response.text}")
    
    report_data = response.json()
    
    # 6) Process the JSON response to extract transaction rows.
    transactions = []
    rows = report_data.get("Rows", {}).get("Row", [])
    
    for row in rows:
        # If the row is a grouping (contains nested Rows), process each nested row.
        if "Rows" in row and "Row" in row["Rows"]:
            for data_row in row["Rows"]["Row"]:
                # Only process rows with type "Data" (ignore any other types).
                if data_row.get("type") != "Data":
                    continue
                col_data = data_row.get("ColData", [])
                # Ensure there are at least 10 columns as expected.
                if len(col_data) < 10:
                    continue
                txn = {
                    "date": col_data[0].get("value", ""),
                    "transaction_type": col_data[1].get("value", ""),
                    "doc_num": col_data[2].get("value", ""),
                    "posting": col_data[3].get("value", ""),
                    "name": col_data[4].get("value", ""),
                    "department": col_data[5].get("value", ""),
                    "memo": col_data[6].get("value", ""),
                    "account": col_data[7].get("value", ""),
                    "split": col_data[8].get("value", ""),
                    "amount": col_data[9].get("value", "")
                }
                transactions.append(txn)
        # If the row is standalone, process it directly.
        else:
            # Optionally, check if row type is "Data".
            if row.get("type") != "Data":
                continue
            col_data = row.get("ColData", [])
            if len(col_data) < 10:
                continue
            txn = {
                "date": col_data[0].get("value", ""),
                "transaction_type": col_data[1].get("value", ""),
                "doc_num": col_data[2].get("value", ""),
                "posting": col_data[3].get("value", ""),
                "name": col_data[4].get("value", ""),
                "department": col_data[5].get("value", ""),
                "memo": col_data[6].get("value", ""),
                "account": col_data[7].get("value", ""),
                "split": col_data[8].get("value", ""),
                "amount": col_data[9].get("value", "")
            }
            transactions.append(txn)
    
    # 7) Apply local filtering if any filters were provided.
    if local_filters:
        transactions = filter_transactions_locally(transactions, local_filters)
    
    return {"transactions": transactions}

#--------------- Filter Transactions Local Def -------------------#

def filter_transactions_locally(transactions: list, local_filters: dict) -> list:
    """
    Filters a list of transaction dictionaries based on provided filter criteria.
    Performs a case-insensitive substring search on the relevant fields.
    
    :param transactions: List of transaction dicts.
    :param local_filters: Dictionary of filter keys and values (e.g., {"vendor": "McDonald's"}).
                          Note: For filtering by vendor, we assume the vendor name is stored in the "name" field.
    :return: Filtered list of transactions.
    """
    filtered = []
    for txn in transactions:
        include = True
        for key, filter_value in local_filters.items():
            # Map "vendor" to "name" since that's where the vendor name appears in the report.
            field = "name" if key == "vendor" else key
            txn_value = txn.get(field, "")
            if filter_value.lower() not in txn_value.lower():
                include = False
                break
        if include:
            filtered.append(txn)
    return filtered

#------------------------------------------------------------#
#------------------- Quickbooks Utils -----------------------#
#------------------------------------------------------------#

#--------------- Refresh Access Token Def -------------------#

def revoke_quickbooks_tokens(refresh_token):
    """
    Revokes the given refresh token with QuickBooks.
    """
    try:
        auth_header = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
        payload = {'token': refresh_token}
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = requests.post(REVOKE_TOKEN_URL, auth=auth_header, data=payload, headers=headers)
        if response.status_code != 200:
            raise Exception(f"Failed to revoke tokens: {response.text}")
        logging.info("QuickBooks tokens revoked successfully.")
    except Exception as e:
        logging.error(f"Error revoking tokens: {e}")
        raise
    
    
def refresh_access_token(user_id):
    """
    Refreshes the QuickBooks access token for an app-based user (one row per user).
    """
    quickbooks_data = get_quickbooks_tokens(user_id)
    if not quickbooks_data:
        raise Exception("No QuickBooks tokens found for this user.")

    refresh_token = quickbooks_data['refresh_token']
    auth_header = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    payload = {'grant_type': 'refresh_token', 'refresh_token': refresh_token}
    headers = {'Accept': 'application/json'}

    response = requests.post(TOKEN_URL, auth=auth_header, data=payload, headers=headers)
    if response.status_code == 200:
        tokens_json = response.json()
        new_access_token = tokens_json['access_token']
        new_refresh_token = tokens_json.get('refresh_token', refresh_token)
        new_expiry = (datetime.utcnow() + timedelta(seconds=tokens_json['expires_in'])).isoformat()

        save_quickbooks_tokens(
            user_id=user_id,
            realm_id=quickbooks_data['realm_id'],
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            token_expiry=new_expiry
        )
        logging.info(f"Access token refreshed for user {user_id}.")
    else:
        logging.error(f"Failed to refresh access token for user_id={user_id}: {response.text}")
        raise Exception(response.text)