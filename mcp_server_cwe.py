import gradio as gr
import json
from app.threat_intel import enrich_with_cwe

# MCP Tool: Standalone CWE Lookup
def get_cwe_details(cwe_id: str):
    """
    Fetches CWE details for a given CWE ID.

    Arguments:
        cwe_id (str): Example 'CWE-416'

    Returns:
        dict: CWE details
    """
    return enrich_with_cwe(cwe_id)

# For local testing UI
with gr.Blocks() as demo:
    gr.Markdown("## CyberSec MCP Tool — CWE Enrichment")

    cwe_input = gr.Textbox(label="Enter CWE ID (e.g. CWE-416)")
    cwe_button = gr.Button("Fetch CWE Details")
    cwe_output = gr.JSON()

    cwe_button.click(fn=get_cwe_details, inputs=[cwe_input], outputs=[cwe_output])

# MCP Server Interface (exposes this tool via MCP)
mcp_server = gr.Interface(
    fn=get_cwe_details,
    inputs=gr.Textbox(label="Enter CWE ID (e.g. CWE-416)"),
    outputs="json",
    live=True
)

if __name__ == "__main__":
    demo.launch(mcp_server=True)
