import gradio as gr
import json
from threat_intel import fetch_cisa_cves

def serialize_cves(cve_list):
    return [cve.model_dump() for cve in cve_list]

def get_latest_threats(cutoff_date: str):
    """
    Fetches CVEs from the CISA KEV catalog filtered by cutoff date,
    enriches them with CVSS scores (via CVE-AWG) and CWE data (via CWE scraper).

    Arguments:
        cutoff_date (str): The date in 'YYYY-MM-DD' format. Only CVEs added on or after this date will be processed.
                           If invalid or empty, the function uses a default cutoff date.

    Returns:
        dict: A dictionary with key 'threats' containing a list of enriched CVE records.
              Each record includes CVE ID, vulnerability details, CVSS score, CWE name,
              CWE consequences, mitigations, and other related fields.
    """
    cves = fetch_cisa_cves(cutoff_date)
    output = serialize_cves(cves)
    safe_output = json.loads(json.dumps({"threats": output}))
    return safe_output

with gr.Blocks() as demo:
    gr.Markdown("## CyberSec MCP Tool")

    with gr.Row():
        date_input = gr.Textbox(label="Enter Cutoff Date (YYYY-MM-DD)", value="2025-05-01")
        generate_button = gr.Button("Generate")

    output_box = gr.JSON()

    generate_button.click(fn=get_latest_threats, inputs=[date_input], outputs=output_box)

# MCP Server Interface
mcp_server = gr.Interface(
    fn=get_latest_threats,
    inputs=gr.Textbox(label="Enter Cutoff Date (YYYY-MM-DD)", value="2025-05-01"),
    outputs="json",
    live=True
)

if __name__ == "__main__":
    demo.launch(mcp_server=True)
