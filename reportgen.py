import sqlite3
import questionary
from docx import Document
from docxtpl import DocxTemplate
import matplotlib.pyplot as plt
import logging
import seaborn as sns
from openai import OpenAI
from docx.shared import Pt, RGBColor
from docx.oxml import OxmlElement

# Initialize OpenAI Client
client = OpenAI(
    api_key=""
)

# Step 1: Database Setup and Queries
def setup_database():
    try:
        conn = sqlite3.connect('vulnerabilities.db')
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
            vulnerability_id INTEGER PRIMARY KEY,
            vulnerability_name TEXT NOT NULL,
            Vulnerability_description TEXT,
            Ease_of_exploit TEXT,
            Ease_of_exploit_description TEXT,
            Impact TEXT,
            Impact_Description TEXT,
            vulnerability_solution TEXT,
            vulnerability_exploitprobability_score REAL,
            severity TEXT,
            cvss3_base_score REAL,
            cvss3_base_vector TEXT,
            vulnerability_references TEXT,
            see_also TEXT
        )''')
        conn.commit()
        conn.close()
        logging.info("Database setup completed successfully.")
    except sqlite3.Error as e:
        logging.error(f"Error setting up database: {e}")

def fetch_vulnerabilities():
    try:
        conn = sqlite3.connect('vulnerabilities.db')
        cursor = conn.cursor()
        cursor.execute('''SELECT
            vulnerability_id, vulnerability_name, Vulnerability_description, Ease_of_exploit,
            Ease_of_exploit_description, Impact, Impact_Description,
            vulnerability_solution, vulnerability_exploitprobability_score, severity,
            cvss3_base_score, cvss3_base_vector, vulnerability_references, see_also
        FROM vulnerabilities''')
        rows = cursor.fetchall()
        conn.close()

        logging.info("Fetched vulnerabilities from the database.")

        # Map rows to dictionaries
        return [
            {
                "vulnerability_id": row[0],
                "vulnerability_name": row[1] or "N/A",
                "vulnerability_description": row[2] or "N/A",
                "Ease_of_exploit": row[3] or "N/A",
                "Ease_of_exploit_description": row[4] or "N/A",
                "Impact": row[5] or "N/A",
                "Impact_Description": row[6] or "N/A",
                "vulnerability_solution": row[7] or "N/A",
                "vulnerability_exploitprobability_score": row[8] or 0.0,
                "severity": row[9] or "N/A",
                "cvss3_base_score": row[10] or 0.0,
                "cvss3_base_vector": row[11] or "N/A",
                "vulnerability_references": row[12] or "N/A",
                "see_also": row[13] or "N/A",
            }
            for row in rows
        ]
    except sqlite3.Error as e:
        logging.error(f"Error fetching vulnerabilities: {e}")
        return []

# Step 2: Basic Info and Scope
def get_basic_info():
    try:
        return {
            "Vendor_Name": questionary.text("Enter Testing Vendor Name:").ask(),
            "Customer_Name": questionary.text("Enter Customer Name:").ask(),
            "Start_Date": questionary.text("Enter Start Date (YYYY-MM-DD):").ask(),
            "End_Date": questionary.text("Enter End Date (YYYY-MM-DD):").ask(),
            "Application_Name": questionary.text("Enter Application Name:").ask(),
            "Author_1": questionary.text("Enter Author 1 Name (e.g., Kendall Lewis):").ask(),
            "Author_2": questionary.text("Enter Author 2 Name (e.g., Liam Henig):").ask(),
            "Security_Score": questionary.text("Enter Security Score (e.g., A/Excellent, B/Good, C/Fair, D/Poor):").ask(),
            "Test_Type": questionary.select(
                "Select Test Type:",
                choices=["Black Box", "Grey Box", "White Box"]
            ).ask(),
            "Hostname": questionary.text("Enter Hostname:").ask(),
            "IP_Address": questionary.text("Enter IP Address:").ask(),
            "UserAcct1": questionary.text("Enter User Account 1:").ask(),
            "UserAcct2": questionary.text("Enter User Account 2:").ask(),
        }
    except Exception as e:
        logging.error(f"Error getting basic info: {e}")
        return {}

def get_vuln_scope():
    try:
        return {
            "service_scope": questionary.checkbox("Select the Scope of the Test (Choose all that apply):",
                                                  choices=["Network", "Web Application", "Mobile Application", "Other"]).ask(),
            "service_detailed_scope": questionary.text("Enter Application Name:").ask(),
        }
    except Exception as e:
        logging.error(f"Error getting vulnerability scope: {e}")
        return {}

# Step 3: Vulnerability Selection
def select_vulnerabilities(vulnerabilities):
    try:
        # Display only the vulnerability names for selection
        choices = [v['vulnerability_name'] for v in vulnerabilities]

        selected_names = questionary.checkbox(
            "Select vulnerabilities to include in the report:", choices=choices
        ).ask()

        if not selected_names:
            logging.warning("No vulnerabilities selected.")
            return []

        # Filter vulnerabilities based on selected names
        return [v for v in vulnerabilities if v['vulnerability_name'] in selected_names]
    except Exception as e:
        logging.error(f"Error selecting vulnerabilities: {e}")
        return []

# Step 4: Narrative Generation
def generate_narrative(vulnerabilities):
    severity_groups = {}
    for v in vulnerabilities:
        severity_groups.setdefault(v['severity'], []).append(v)

    prompt = "Generate a concise executive summary for the following grouped vulnerabilities:\n\n"
    for severity, vulns in severity_groups.items():
        prompt += f"Severity: {severity}\n"
        for v in vulns:
            prompt += f"- {v['vulnerability_name']} (Severity: {v['severity']})\n"
        prompt += "\n"

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=30,
            temperature=0.7,
        )
        return response.choices[0].message["content"]
    except Exception as e:
        logging.error(f"Error generating narrative: {e}")
        return "Error generating narrative."

# Step 5: Heatmap Generation
def generate_heatmap(vulnerabilities):
    try:
        plt.figure(figsize=(10, 6))
        sns.heatmap(
            [[v['severity'], v['vulnerability_exploitprobability_score']] for v in vulnerabilities],
            annot=True, fmt=".2f", cmap="YlGnBu",
            xticklabels=["Severity", "Exploit Probability"]
        )
        plt.title("Vulnerability Heatmap")
        plt.savefig("heatmap.png")
        logging.info("Heatmap generated and saved as heatmap.png.")
    except Exception as e:
        logging.error(f"Error generating heatmap: {e}")

# Step 6: Generate Report

def add_vulnerability_table(doc, selected_vulnerabilities):
    """
    Adds a vulnerability table to the document, including only the selected vulnerabilities,
    sorted by impact and ease of exploit.
    """
    # Sort vulnerabilities by impact and ease_of_exploit fields
    sorted_vulnerabilities = sorted(
        selected_vulnerabilities,
        key=lambda v: (v.get('Impact', ''), v.get('Ease_of_exploit', ''))
    )

    # Find the existing table in the document with the header "Vulnerability Description"
    table_found = False
    for table in doc.tables:
        if table.rows[0].cells[0].text.strip() == "Vulnerability Description":
            table_found = True
            # Clear existing rows (excluding the header)
            while len(table.rows) > 1:
                table.rows[-1]._element.getparent().remove(table.rows[-1]._element)

            # Add the selected vulnerabilities to the table
            for vuln in sorted_vulnerabilities:
                row_cells = table.add_row().cells
                row_cells[0].text = f"{vuln['vulnerability_name']}\n{vuln['vulnerability_description'] or 'N/A'}"
                row_cells[1].text = f"{vuln.get('Ease_of_exploit', 'N/A')}\n{vuln.get('Ease_of_exploit_description', 'N/A')}"
                row_cells[2].text = f"{vuln.get('Impact', 'N/A')}\n{vuln.get('Impact_Description', 'N/A')}"
                row_cells[3].text = vuln['vulnerability_solution'] or "N/A"

            break

    if not table_found:
        logging.error("Table with header 'Vulnerability Description' not found in the document.")

def generate_report(template_path, output_path, placeholders, vulnerabilities):
? Select vulnerabilities to include in the report: done (4 selections)
ERROR:root:Error generating narrative: Connection error.
ERROR:root:Error generating heatmap: could not convert string to float: 'High'

┌──(klewis㉿kali)-[~/tools/pentestrptgenerator]
└─$ vi reportgen.py

┌──(klewis㉿kali)-[~/tools/pentestrptgenerator]
└─$ cat reportgen.py
import sqlite3
import questionary
from docx import Document
from docxtpl import DocxTemplate
import matplotlib.pyplot as plt
import logging
import seaborn as sns
from openai import OpenAI
from docx.shared import Pt, RGBColor
from docx.oxml import OxmlElement

# Initialize OpenAI Client
client = OpenAI(
    api_key=""
)

# Step 1: Database Setup and Queries
def setup_database():
    try:
        conn = sqlite3.connect('vulnerabilities.db')
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
            vulnerability_id INTEGER PRIMARY KEY,
            vulnerability_name TEXT NOT NULL,
            Vulnerability_description TEXT,
            Ease_of_exploit TEXT,
            Ease_of_exploit_description TEXT,
            Impact TEXT,
            Impact_Description TEXT,
            vulnerability_solution TEXT,
            vulnerability_exploitprobability_score REAL,
            severity TEXT,
            cvss3_base_score REAL,
            cvss3_base_vector TEXT,
            vulnerability_references TEXT,
            see_also TEXT
        )''')
        conn.commit()
        conn.close()
        logging.info("Database setup completed successfully.")
    except sqlite3.Error as e:
        logging.error(f"Error setting up database: {e}")

def fetch_vulnerabilities():
    try:
        conn = sqlite3.connect('vulnerabilities.db')
        cursor = conn.cursor()
        cursor.execute('''SELECT
            vulnerability_id, vulnerability_name, Vulnerability_description, Ease_of_exploit,
            Ease_of_exploit_description, Impact, Impact_Description,
            vulnerability_solution, vulnerability_exploitprobability_score, severity,
            cvss3_base_score, cvss3_base_vector, vulnerability_references, see_also
        FROM vulnerabilities''')
        rows = cursor.fetchall()
        conn.close()

        logging.info("Fetched vulnerabilities from the database.")

        # Map rows to dictionaries
        return [
            {
                "vulnerability_id": row[0],
                "vulnerability_name": row[1] or "N/A",
                "vulnerability_description": row[2] or "N/A",
                "Ease_of_exploit": row[3] or "N/A",
                "Ease_of_exploit_description": row[4] or "N/A",
                "Impact": row[5] or "N/A",
                "Impact_Description": row[6] or "N/A",
                "vulnerability_solution": row[7] or "N/A",
                "vulnerability_exploitprobability_score": row[8] or 0.0,
                "severity": row[9] or "N/A",
                "cvss3_base_score": row[10] or 0.0,
                "cvss3_base_vector": row[11] or "N/A",
                "vulnerability_references": row[12] or "N/A",
                "see_also": row[13] or "N/A",
            }
            for row in rows
        ]
    except sqlite3.Error as e:
        logging.error(f"Error fetching vulnerabilities: {e}")
        return []

# Step 2: Basic Info and Scope
def get_basic_info():
    try:
        return {
            "Vendor_Name": questionary.text("Enter Testing Vendor Name:").ask(),
            "Customer_Name": questionary.text("Enter Customer Name:").ask(),
            "Start_Date": questionary.text("Enter Start Date (YYYY-MM-DD):").ask(),
            "End_Date": questionary.text("Enter End Date (YYYY-MM-DD):").ask(),
            "Application_Name": questionary.text("Enter Application Name:").ask(),
            "Author_1": questionary.text("Enter Author 1 Name (e.g., Kendall Lewis):").ask(),
            "Author_2": questionary.text("Enter Author 2 Name (e.g., Liam Henig):").ask(),
            "Security_Score": questionary.text("Enter Security Score (e.g., A/Excellent, B/Good, C/Fair, D/Poor):").ask(),
            "Test_Type": questionary.select(
                "Select Test Type:",
                choices=["Black Box", "Grey Box", "White Box"]
            ).ask(),
            "Hostname": questionary.text("Enter Hostname:").ask(),
            "IP_Address": questionary.text("Enter IP Address:").ask(),
            "UserAcct1": questionary.text("Enter User Account 1:").ask(),
            "UserAcct2": questionary.text("Enter User Account 2:").ask(),
        }
    except Exception as e:
        logging.error(f"Error getting basic info: {e}")
        return {}

def get_vuln_scope():
    try:
        return {
            "service_scope": questionary.checkbox("Select the Scope of the Test (Choose all that apply):",
                                                  choices=["Network", "Web Application", "Mobile Application", "Other"]).ask(),
            "service_detailed_scope": questionary.text("Enter Application Name:").ask(),
        }
    except Exception as e:
        logging.error(f"Error getting vulnerability scope: {e}")
        return {}

# Step 3: Vulnerability Selection
def select_vulnerabilities(vulnerabilities):
    try:
        # Display only the vulnerability names for selection
        choices = [v['vulnerability_name'] for v in vulnerabilities]

        selected_names = questionary.checkbox(
            "Select vulnerabilities to include in the report:", choices=choices
        ).ask()

        if not selected_names:
            logging.warning("No vulnerabilities selected.")
            return []

        # Filter vulnerabilities based on selected names
        return [v for v in vulnerabilities if v['vulnerability_name'] in selected_names]
    except Exception as e:
        logging.error(f"Error selecting vulnerabilities: {e}")
        return []

# Step 4: Narrative Generation
def generate_narrative(vulnerabilities):
    severity_groups = {}
    for v in vulnerabilities:
        severity_groups.setdefault(v['severity'], []).append(v)

    prompt = "Generate a concise executive summary for the following grouped vulnerabilities:\n\n"
    for severity, vulns in severity_groups.items():
        prompt += f"Severity: {severity}\n"
        for v in vulns:
            prompt += f"- {v['vulnerability_name']} (Severity: {v['severity']})\n"
        prompt += "\n"

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=30,
            temperature=0.7,
        )
        return response.choices[0].message["content"]
    except Exception as e:
        logging.error(f"Error generating narrative: {e}")
        return "Error generating narrative."

# Step 5: Heatmap Generation
def generate_heatmap(vulnerabilities):
    try:
        plt.figure(figsize=(10, 6))
        sns.heatmap(
            [[v['severity'], v['vulnerability_exploitprobability_score']] for v in vulnerabilities],
            annot=True, fmt=".2f", cmap="YlGnBu",
            xticklabels=["Severity", "Exploit Probability"]
        )
        plt.title("Vulnerability Heatmap")
        plt.savefig("heatmap.png")
        logging.info("Heatmap generated and saved as heatmap.png.")
    except Exception as e:
        logging.error(f"Error generating heatmap: {e}")

# Step 6: Generate Report

def add_vulnerability_table(doc, selected_vulnerabilities):
    """
    Adds a vulnerability table to the document, including only the selected vulnerabilities,
    sorted by impact and ease of exploit.
    """
    # Sort vulnerabilities by impact and ease_of_exploit fields
    sorted_vulnerabilities = sorted(
        selected_vulnerabilities,
        key=lambda v: (v.get('Impact', ''), v.get('Ease_of_exploit', ''))
    )

    # Find the existing table in the document with the header "Vulnerability Description"
    table_found = False
    for table in doc.tables:
        if table.rows[0].cells[0].text.strip() == "Vulnerability Description":
            table_found = True
            # Clear existing rows (excluding the header)
            while len(table.rows) > 1:
                table.rows[-1]._element.getparent().remove(table.rows[-1]._element)

            # Add the selected vulnerabilities to the table
            for vuln in sorted_vulnerabilities:
                row_cells = table.add_row().cells
                row_cells[0].text = f"{vuln['vulnerability_name']}\n{vuln['vulnerability_description'] or 'N/A'}"
                row_cells[1].text = f"{vuln.get('Ease_of_exploit', 'N/A')}\n{vuln.get('Ease_of_exploit_description', 'N/A')}"
                row_cells[2].text = f"{vuln.get('Impact', 'N/A')}\n{vuln.get('Impact_Description', 'N/A')}"
                row_cells[3].text = vuln['vulnerability_solution'] or "N/A"

            break

    if not table_found:
        logging.error("Table with header 'Vulnerability Description' not found in the document.")

def generate_report(template_path, output_path, placeholders, vulnerabilities):
    """
    Generates a pentest report from a template.
    """
    try:
        # Load the template
        template = DocxTemplate(template_path)

        # Render placeholders
        template.render(placeholders)

        # Load the rendered template as a Document object
        doc = template.docx

        # Update the existing formatted table with vulnerabilities
        add_vulnerability_table(doc, vulnerabilities)

        # Save the updated document
        doc.save(output_path)
        logging.info(f"Report generated successfully at: {output_path}")
    except Exception as e:
        logging.error(f"Error generating report: {e}")

# Main Workflow
def main():
    # Step 1: Database setup
    setup_database()

    # Step 2: Fetch vulnerabilities
    vulnerabilities = fetch_vulnerabilities()
    if not vulnerabilities:
        logging.error("No vulnerabilities found in the database. Exiting.")
        return

    # Step 3: Basic Info and Scope
    basic_info = get_basic_info()
    vuln_scope = get_vuln_scope()

    # Step 4: Vulnerability Selection
    selected_vulnerabilities = select_vulnerabilities(vulnerabilities)
    if not selected_vulnerabilities:
        logging.warning("No vulnerabilities selected for the report. Exiting.")
        return

    # Step 5: Narrative Generation
    narrative = generate_narrative(selected_vulnerabilities)

    # Step 6: Heatmap Generation
    generate_heatmap(selected_vulnerabilities)

    # Step 7: Report Generation
    # Set template path and output path
    placeholders = {**basic_info, **vuln_scope, "Narrative": narrative}
    template_path = "WebApplicationTestSample.docx"  # Replace with your template file
    output_path = f"{placeholders['Customer_Name']}_Pentest_Report.docx"
    generate_report(template_path, output_path, placeholders, selected_vulnerabilities)

if __name__ == "__main__":
    main()
