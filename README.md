# QuickBooks GPT Middleware

## Overview

**QuickBooks GPT Middleware** is a Flask-based application that acts as a bridge between OpenAI's API and QuickBooks, enabling advanced business data analysis through AI. Hosted on Render, this middleware provides endpoints to fetch and analyze financial data, making it accessible to OpenAI integrations or other API clients.

---

## Features

- **Company Information Retrieval**: Retrieve company details from QuickBooks via API.
- **AI-Driven Analysis**: Use OpenAI's GPT to generate insights based on financial and company data.
- **Financial Reports Access**: Fetch detailed financial reports such as Profit & Loss, Balance Sheets, and more.
- **Secure Authentication**: OAuth2 integration for securely accessing QuickBooks APIs.
- **User Interface**: Interactive templates for dashboards and analysis visualization.

---

## Usage

### Online Access (Primary Method)

The middleware is hosted on Render and accessible at:

- **Base URL**: [https://quickbooks-gpt-app.onrender.com](https://quickbooks-gpt-app.onrender.com)

---

## API Endpoints

The application exposes the following key endpoints for API clients or tools like OpenAI’s custom GPT integrations:

### `/business-info` (GET)
- **Description**: Fetch basic company details from QuickBooks.
- **Response**:
  ```json
  {
    "companyName": "Example Company",
    "legalName": "Example Legal Name",
    "address": "123 Business St.",
    "phone": "123-456-7890",
    "email": "contact@example.com"
  }
  ```

### `/analyze` (GET)
- **Description**: Analyze company information with OpenAI.
- **Response**:
  ```json
  {
    "analysis": "This company has consistent revenue growth...",
    "originalData": {
      "companyName": "Example Company",
      "legalName": "Example Legal Name",
      "address": "123 Business St.",
      "phone": "123-456-7890",
      "email": "contact@example.com"
    }
  }
  ```

### `/list-reports` (GET)
- **Description**: List all supported QuickBooks financial reports.
- **Response**:
  ```json
  {
    "availableReports": ["ProfitAndLoss", "BalanceSheet", ...],
    "message": "Use the /fetch-reports endpoint with a valid reportType from this list."
  }
  ```

### `/fetch-reports` (GET)
- **Description**: Fetch a specific financial report from QuickBooks.
- **Parameters**:
  - `reportType` (required): The type of report to fetch (e.g., `ProfitAndLoss`, `BalanceSheet`).
  - `startDate` (optional): Start date for the report in `YYYY-MM-DD` format.
  - `endDate` (optional): End date for the report in `YYYY-MM-DD` format.
- **Response**:
  ```json
  {
    "reportType": "ProfitAndLoss",
    "data": { ... }
  }
  ```

### `/analyze-reports` (POST)
- **Description**: Analyze a fetched financial report using OpenAI.
- **Body**:
  ```json
  {
    "report": { ... }
  }
  ```
- **Response**:
  ```json
  {
    "analysis": "Based on the financial data...",
    "originalData": { ... }
  }
  ```

---

## How It Works

### Render Hosting:
The middleware is hosted on Render for seamless online access.
- **Base URL**: [https://quickbooks-gpt-app.onrender.com](https://quickbooks-gpt-app.onrender.com)

### GitHub Integration:
- Any updates to the middleware code are pushed to the GitHub repository.
- Render automatically deploys the latest changes when commits are pushed.

### Supabase:
- Supabase is used to securely store and manage QuickBooks OAuth2 tokens.
- Tokens are refreshed automatically when they expire.

### QuickBooks API:
- Provides access to company information and financial reports.
- Requires OAuth2 authentication for secure data retrieval.

### OpenAI API:
- Integrated for performing AI-driven analysis of financial and company data.

---

## Development (Optional Local Setup)

If you need to run the middleware locally for testing or development:

### Prerequisites
Ensure the following are installed:
- Python 3.10 or newer
- Pip (Python package manager)

### Clone the Repository
```bash
git clone https://github.com/your-username/quickbooks-gpt-middleware.git
cd quickbooks-gpt-middleware
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Environment Variables
Create a `.env` file in the root directory with the following:
```plaintext
FLASK_ENV=development
FLASK_SECRET_KEY=your_secret_key
SUPABASE_URL=your_supabase_url
SUPABASE_KEY=your_supabase_key
QB_CLIENT_ID=your_quickbooks_client_id
QB_CLIENT_SECRET=your_quickbooks_client_secret
REDIRECT_URI=http://localhost:5000/callback
OPENAI_API_KEY=your_openai_api_key
```

### Run Locally
```bash
python app.py
```
Navigate to `http://localhost:5000`.

---

## Templates and Styles

The middleware includes the following HTML templates:

- **Dashboard (`dashboard.html`)**: Displays company data and buttons for API interactions.
- **Analysis (`analysis.html`)**: Displays AI-generated insights and original company data.
- **Error Template**: Used for displaying error messages.
- **Index Page**: Default landing page.

### Styles
Custom styles for templates are located in `static/styles.css`. These include:
- Button styles
- Layout enhancements
- Responsive design
- Highlighting for analysis results

---

## Deployment on Render

Push your changes to GitHub:
```bash
git add .
git commit -m "Update middleware"
git push origin main
```
Render will automatically deploy the latest commit.

---

## OpenAPI Schema

Here is the OpenAPI schema defining the middleware's API:
```yaml
openapi: 3.1.0
info:
  title: QuickBooks Middleware API
  description: Simplified API for accessing and analyzing QuickBooks data.
  version: 1.0.0
servers:
  - url: https://quickbooks-gpt-app.onrender.com
paths:
  /business-info:
    get:
      operationId: getBusinessInfo
      summary: Fetch business information
      responses:
        '200':
          description: Successful response
          content:
            application/json:
              schema:
                type: object
                properties:
                  companyName:
                    type: string
                  legalName:
                    type: string
                  address:
                    type: string
                  phone:
                    type: string
                  email:
                    type: string
  /fetch-reports:
    get:
      operationId: fetchReports
      summary: Fetch financial reports
      parameters:
        - name: reportType
          in: query
          required: true
          schema:
            type: string
        - name: startDate
          in: query
          required: false
          schema:
            type: string
            format: date
        - name: endDate
          in: query
          required: false
          schema:
            type: string
            format: date
      responses:
        '200':
          description: Successful response
          content:
            application/json:
              schema:
                type: object
                properties:
                  reportType:
                    type: string
                  data:
                    type: object
  /analyze:
    get:
      operationId: analyzeBusinessInfo
      summary: Analyze business information
      responses:
        '200':
          description: Successful analysis
          content:
            application/json:
              schema:
                type: object
                properties:
                  analysis:
                    type: string
                  originalData:
                    type: object
```

---

## Troubleshooting

- **OAuth Errors**: Verify that QuickBooks credentials and redirect URI are correctly configured.
- **Token Issues**: Ensure Supabase is set up to store and refresh tokens.
- **API Failures**: Check logs on Render for detailed error messages.

---

## Contributing

Contributions are welcome! Submit issues or pull requests on GitHub to improve the project.
