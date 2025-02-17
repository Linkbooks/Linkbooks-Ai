import logging
import jwt
from flask import Blueprint, request, jsonify, render_template, redirect



# Create the auth blueprint
features_bp = Blueprint('features', __name__, url_prefix='/features')

# Load Supabase client
config = get_config()
supabase = create_client(config.SUPABASE_URL, config.SUPABASE_KEY)



# ------------------------------------------
#             Get Business Info
# ------------------------------------------
@features_bp.route('/business-info', methods=['GET'])
def business_info():
    """
    Retrieves the user's company information from QuickBooks if they have a valid session.
    """
    try:
        chat_session_id = request.args.get('chatSessionId')
        session_token = request.cookies.get('session_token')

        if not chat_session_id and not session_token:
            logging.error("Missing chatSessionId and session token.")
            return jsonify({"error": "chatSessionId or session token is required"}), 400

        user_id = None
        if session_token:
            try:
                decoded = jwt.decode(session_token, SECRET_KEY, algorithms=["HS256"])
                user_id = decoded.get("user_id")
            except jwt.ExpiredSignatureError:
                logging.error("Session token expired.")
                return jsonify({"error": "Session token expired. Please log in again."}), 401
            except jwt.InvalidTokenError:
                logging.error("Invalid session token.")
                return jsonify({"error": "Invalid session token. Please log in again."}), 401

        # -- If chatSessionId is provided, find the user_id first --
        if chat_session_id and not user_id:
            user_lookup = supabase.table("user_profiles").select("id").eq("chat_session_id", chat_session_id).execute()
            if user_lookup.data:
                user_id = user_lookup.data[0]["id"]
            else:
                logging.error(f"No user found for chatSessionId: {chat_session_id}")
                return jsonify({"error": "User not found for given chatSessionId"}), 404

        if not user_id:
            logging.error("No valid identifier for token retrieval.")
            return jsonify({"error": "No valid identifier for token retrieval."}), 400

        # -- Fetch QuickBooks tokens using user_id --
        tokens_response = supabase.table("quickbooks_tokens").select("*").eq("user_id", user_id).execute()

        if not tokens_response.data:
            logging.error(f"No tokens found for user {user_id}")
            return jsonify({"error": "No QuickBooks tokens found. Please log in again."}), 404

        tokens = tokens_response.data[0]
        access_token = tokens["access_token"]
        realm_id = tokens["realm_id"]
        expiry = tokens["token_expiry"]

        if not access_token or not realm_id:
            logging.error("Missing access_token or realm_id.")
            return jsonify({"error": "Invalid QuickBooks tokens."}), 400

        # -- Check for expiry / refresh if needed --
        if expiry and datetime.utcnow() > datetime.fromisoformat(expiry):
            logging.info("Access token expired. Attempting refresh...")
            try:
                refresh_access_token(user_id)  # Refresh the token
                updated_tokens = supabase.table("quickbooks_tokens").select("*").eq("user_id", user_id).execute()
                if updated_tokens.data:
                    access_token = updated_tokens.data[0]["access_token"]
                    realm_id = updated_tokens.data[0]["realm_id"]
                else:
                    raise Exception("No updated tokens after refresh.")
            except Exception as e:
                logging.error(f"Failed to refresh tokens: {e}")
                return jsonify({"error": "Failed to refresh tokens. Please log in again."}), 401

        # -- Call QuickBooks API to get company info --
        company_info = get_company_info(user_id)

        return jsonify({
            "companyName": company_info.get("CompanyName"),
            "legalName": company_info.get("LegalName"),
            "address": company_info.get("CompanyAddr", {}).get("Line1"),
            "phone": company_info.get("PrimaryPhone", {}).get("FreeFormNumber"),
            "email": company_info.get("Email", {}).get("Address"),
        }), 200

    except Exception as e:
        logging.error(f"Error in /business-info: {e}")
        return jsonify({"error": str(e)}), 500



# ------------------------------------------
# Fetch Reports for ChatGPT sessions
# ------------------------------------------
@features_bp.route('/fetch-reports', methods=['GET'])
def fetch_reports_route():
    """
    Fetches a QuickBooks report for a given chatSessionId or userId,
    and delegates token handling + refresh logic to fetch_report().
    """
    try:
        chat_session_id = request.args.get('chatSessionId')
        session_token = request.cookies.get('session_token')

        # 1) If we have a session token, decode user_id
        user_id = None
        if session_token:
            try:
                decoded = jwt.decode(session_token, SECRET_KEY, algorithms=["HS256"])
                user_id = decoded.get("user_id")
            except jwt.ExpiredSignatureError:
                logging.error("Session token expired.")
                return jsonify({"error": "Session token expired. Please log in again."}), 401
            except jwt.InvalidTokenError:
                logging.error("Invalid session token.")
                return jsonify({"error": "Invalid session token. Please log in again."}), 401

        # 2) If no user_id from session_token, but we have chatSessionId, find user_id from user_profiles
        if not user_id and chat_session_id:
            user_lookup = supabase.table("user_profiles").select("id").eq("chat_session_id", chat_session_id).execute()
            if user_lookup.data:
                user_id = user_lookup.data[0]["id"]
            else:
                logging.error(f"No user found for chatSessionId: {chat_session_id}")
                return jsonify({"error": "User not found for given chatSessionId"}), 404

        if not user_id:
            logging.error("No user_id found via session token or chat_session_id.")
            return jsonify({"error": "No user_id found. Please log in or link session."}), 401

        # 3) Extract the needed query parameters
        report_type = request.args.get("reportType")
        start_date = request.args.get("startDate")
        end_date = request.args.get("endDate")

        # 4) Let fetch_report handle retrieval/refresh of tokens
        report_data = fetch_report(
            user_id=user_id,
            report_type=report_type,
            start_date=start_date,
            end_date=end_date
        )

        # 5) Return the resulting JSON
        return jsonify({
            "reportType": report_type,
            "data": report_data
        }), 200

    except Exception as e:
        logging.error(f"Error in /fetch-reports: {e}")
        return jsonify({"error": str(e)}), 500
    

@features_bp.route('/list-reports', methods=['GET'])
def list_reports():
    """
    Returns a list of supported QuickBooks reports.
    """
    try:
        available_reports = get_reports()
        return {
            "availableReports": available_reports,
            "message": "Use the /fetch-reports endpoint with ?reportType=<one of these>."
        }, 200
    except Exception as e:
        logging.error(f"Error listing reports: {e}")
        return {"error": str(e)}, 500

# ------------------------------------------
# analyze-reports
# ------------------------------------------
@features_bp.route('/analyze-reports', methods=['POST'])
def analyze_reports():
    """
    Sends retrieved report data to OpenAI for an example analysis.
    """
    try:
        reports = request.json
        if not reports or not isinstance(reports, dict):
            return {"error": "Invalid or missing report data. Expected a JSON object."}, 400

        prompt = f"Analyze the following financial data:\n{reports}"
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300
        )
        analysis = response.choices[0].message.content
        return {"analysis": analysis, "originalData": reports}, 200
    except Exception as e:
        logging.error(f"Error analyzing reports: {e}")
        return {"error": str(e)}, 500
    

#-------------- Fetch Transactions AI Route --------------#

@features_bp.route('/fetch-transactions-ai', methods=['GET'])
def fetch_transactions_ai():
    """
    Fetches transactions from QuickBooks, then processes them using OpenAI for intelligent filtering.
    
    Example:
    https://linkbooksai.com/fetch-transactions-ai?start_date=2024-08-01&end_date=2024-08-31&query=Find all food places over £20
    
    The 'query' parameter is used to instruct OpenAI on filtering.
    """
    try:
        # 1️⃣ Get session token from cookies
        session_token = request.cookies.get('session_token')
        if not session_token:
            return jsonify({"error": "No session token provided."}), 401

        # 2️⃣ Decode session token to get user_id
        try:
            decoded = jwt.decode(session_token, SECRET_KEY, algorithms=["HS256"])
            user_id = decoded.get("user_id")
        except Exception as e:
            logging.error("Error decoding session token: " + str(e))
            return jsonify({"error": "Invalid or expired session token."}), 401

        if not user_id:
            return jsonify({"error": "No user_id found in session token."}), 401

        # 3️⃣ Get date range & AI query from query params
        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")
        query = request.args.get("query")  # Example: "Find all food places over £20"

        if not start_date or not end_date or not query:
            return jsonify({"error": "start_date, end_date, and query parameters are required."}), 400

        # 4️⃣ Fetch all transactions from QuickBooks
        transactions = get_qb_transactions_raw(user_id, start_date, end_date)

        # 5️⃣ Determine AI Model (GPT-3.5 Turbo vs GPT-4 Turbo)
        use_gpt4 = should_use_gpt4(query)
        model = "gpt-4-turbo" if use_gpt4 else "gpt-3.5-turbo"

        logging.info(f"Using {model} for AI filtering")

        # 6️⃣ Call OpenAI for filtering
        gpt_response = ask_gpt_to_filter(transactions, query, model)

        # 7️⃣ Return the AI-filtered transactions
        return jsonify({"transactions": gpt_response}), 200

    except Exception as e:
        logging.error("Error in /fetch-transactions-ai: " + str(e))
        return jsonify({"error": str(e)}), 500


#-------------- Fetch Transactions Classic Route --------------#
@features_bp.route('/fetch-transactions', methods=['GET'])
def fetch_transactions_route():
    """
    Fetches the TransactionList report from QuickBooks using dynamic query parameters.
    
    Query parameters such as startDate, endDate, date_macro, payment_method, etc. are sent directly.
    Parameters like vendor, customer, name, department, and memo are removed from the QB request
    and applied locally after the full report is returned.
    
    Example usage:
      /fetch-transactions?chatSessionId=...&startDate=2024-08-01&endDate=2024-08-31&vendor=McDonald's
    """
    try:
        chat_session_id = request.args.get('chatSessionId')
        session_token = request.cookies.get('session_token')
        user_id = None

        # 1) Extract user_id from the session token if available.
        if session_token:
            try:
                decoded = jwt.decode(session_token, SECRET_KEY, algorithms=["HS256"])
                user_id = decoded.get("user_id")
            except jwt.ExpiredSignatureError:
                logging.error("Session token expired.")
                return jsonify({"error": "Session token expired. Please log in again."}), 401
            except jwt.InvalidTokenError:
                logging.error("Invalid session token.")
                return jsonify({"error": "Invalid session token. Please log in again."}), 401

        # 2) If not available, look up user_id via chatSessionId.
        if not user_id and chat_session_id:
            user_lookup = supabase.table("user_profiles").select("id").eq("chat_session_id", chat_session_id).execute()
            if user_lookup.data:
                user_id = user_lookup.data[0]["id"]
            else:
                logging.error(f"No user found for chatSessionId: {chat_session_id}")
                return jsonify({"error": "User not found for given chatSessionId"}), 404

        if not user_id:
            logging.error("No user_id found via session token or chatSessionId.")
            return jsonify({"error": "No user_id found. Please log in or link session."}), 401

        # 3) Build a dictionary of allowed QuickBooks query parameters from the request.
        allowed_params = [
            "date_macro", "payment_method", "duedate_macro", "arpaid", "bothamount",
            "transaction_type", "docnum", "start_moddate", "source_account_type",
            "group_by", "start_date", "department", "start_duedate", "columns",
            "end_duedate", "end_date", "memo", "appaid", "moddate_macro", "printed",
            "createdate_macro", "cleared", "customer", "qzurl", "term", "end_createdate",
            "name", "sort_by", "sort_order", "start_createdate", "end_moddate"
        ]
        qb_params = {}
        for param in allowed_params:
            value = request.args.get(param)
            if value is not None:
                qb_params[param] = value

        # 4) Also capture parameters that require local filtering (e.g., vendor).
        for key in ["vendor"]:
            value = request.args.get(key)
            if value is not None:
                qb_params[key] = value

        # 5) Call the helper to fetch and filter transactions.
        transactions_data = fetch_transactions(user_id=user_id, qb_params=qb_params)

        # 6) Return the sanitized transactions.
        return jsonify({"data": transactions_data}), 200

    except Exception as e:
        logging.error(f"Error in /fetch-transactions: {e}")
        return jsonify({"error": str(e)}), 500
    
    
@features_bp.route('/filter-transactions', methods=['POST'])
def filter_transactions():
    try:
        data = request.json
        query = data.get("query")
        user_id = data.get("user_id")
        start_date = data.get("start_date")
        end_date = data.get("end_date")
        transactions = get_qb_transactions_raw(user_id, start_date, end_date)

        # Determine complexity
        use_gpt4 = should_use_gpt4(query)

        # Select model
        model = "gpt-4-turbo" if use_gpt4 else "gpt-3.5-turbo"

        logging.info(f"Using {model} for filtering")

        gpt_response = ask_gpt_to_filter(transactions, query, model)
        return jsonify(gpt_response)

    except Exception as e:
        logging.error(f"Error in /filter-transactions: {str(e)}")
        return jsonify({"error": str(e)}), 500


# ------------------------------------------#
#             Company Audit
# ------------------------------------------#
@features_bp.route('/audit', methods=['GET'])
def audit():
    """
    Fetches relevant financial reports and business info from QuickBooks,
    then analyzes the company's financial health and suggests improvements.
    """
    try:
        chat_session_id = request.args.get('chatSessionId')
        session_token = request.cookies.get('session_token')

        if not chat_session_id and not session_token:
            logging.error("Missing chatSessionId and session token.")
            return jsonify({"error": "chatSessionId or session token is required"}), 400

        user_id = None
        if session_token:
            try:
                decoded = jwt.decode(session_token, SECRET_KEY, algorithms=["HS256"])
                user_id = decoded.get("user_id")
            except jwt.ExpiredSignatureError:
                logging.error("Session token expired.")
                return jsonify({"error": "Session token expired. Please log in again."}), 401
            except jwt.InvalidTokenError:
                logging.error("Invalid session token.")
                return jsonify({"error": "Invalid session token. Please log in again."}), 401

        # -- If chatSessionId is provided, find the user_id first --
        if chat_session_id and not user_id:
            user_lookup = supabase.table("user_profiles").select("id").eq("chat_session_id", chat_session_id).execute()
            if user_lookup.data:
                user_id = user_lookup.data[0]["id"]
            else:
                logging.error(f"No user found for chatSessionId: {chat_session_id}")
                return jsonify({"error": "User not found for given chatSessionId"}), 404

        if not user_id:
            logging.error("No valid identifier for token retrieval.")
            return jsonify({"error": "No valid identifier for token retrieval."}), 400

        # -- Fetch company info from QuickBooks --
        try:
            company_info = get_company_info(user_id)
        except Exception as e:
            logging.error(f"Error fetching company info: {e}")
            return jsonify({"error": "Failed to retrieve company info. Please check your QuickBooks connection."}), 500

        if not company_info:
            return jsonify({"error": "Company info is empty or unavailable."}), 404

        # -- Fetch relevant financial reports --
        # Fetch relevant financial reports
        reports_to_fetch = ["ProfitAndLoss", "BalanceSheet", "CashFlow"]
        report_data = {}
        failed_reports = []

        for report in reports_to_fetch:
            try:
                report_data[report] = fetch_report(user_id, report)
            except Exception as e:
                logging.warning(f"Could not fetch {report}: {e}")
                failed_reports.append(report)

        # ✅ Instead of failing if all reports are missing, return what we got.
        if not report_data:
            return jsonify({
                "warning": "No financial reports could be retrieved. Ensure QuickBooks is connected.",
                "reports": {},
                "failedReports": failed_reports
            }), 200  # ✅ Return a success response with warning instead of failing


        # -- Construct AI Prompt for Financial Analysis --
        prompt = (
            "Analyze the following company's financial data and business information. "
            "Provide insights into financial health, risks, opportunities, and improvement strategies.\n\n"
            f"**Company Details:**\n"
            f"Company Name: {company_info.get('CompanyName')}\n"
            f"Legal Name: {company_info.get('LegalName')}\n"
            f"Address: {company_info.get('CompanyAddr', {}).get('Line1', 'N/A')}\n"
            f"Phone: {company_info.get('PrimaryPhone', {}).get('FreeFormNumber', 'N/A')}\n"
            f"Email: {company_info.get('Email', {}).get('Address', 'N/A')}\n\n"
            "**Financial Reports:**\n"
        )

        for report_name, data in report_data.items():
            prompt += f"\n**{report_name} Report:**\n{data}\n"

        prompt += "\nBased on the above data, provide an assessment of the company's financial standing, potential risks, and recommendations for improvement."

        # -- Send prompt to OpenAI for analysis --
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500,
            temperature=0.7
        )

        analysis = response.choices[0].message.content

        # -- Return results --
        return render_template('audit.html', analysis=analysis, data={"company_info": company_info, "reports": report_data})

    except Exception as e:
        logging.error(f"Error in /audit: {e}")
        return jsonify({"error": str(e)}), 500
