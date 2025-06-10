import gradio as gr
import os
import openai
from mcp import StdioServerParameters
from smolagents import InferenceClientModel, CodeAgent, MCPClient
from smolagents import OpenAIServerModel
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
HUGGINGFACE_API_TOKEN = os.getenv("HUGGINGFACE_API_KEY")


model = OpenAIServerModel(
    model_id= "gpt-3.5-turbo",
    api_key=OPENAI_API_KEY  # This is your OpenAI key
)


mcp_client = MCPClient({
            "url": "https://Agents-MCP-Hackathon-cybersec_intel-tool.hf.space/gradio_api/mcp/sse",
            "transport": "sse"
        })
tools = mcp_client.get_tools()

agent = CodeAgent(
    tools=tools,
    model=model,
)

def chat_fn(message, history):
    return str(agent.run(message))

demo = gr.ChatInterface(
    fn=chat_fn,
    title="Cyber Threat MCP Agent",
    description="An OpenAI GPT agent that invokes local MCP tools.",
    examples=[
        "Summarize latest threats after 2025-06-08",
    ],
)

if __name__ == "__main__":
    demo.launch()

