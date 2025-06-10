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


mcp_client = MCPClient(
            {"url": "http://127.0.0.1:7860/gradio_api/mcp/sse"} 
        )
tools = mcp_client.get_tools()

agent = CodeAgent(
    tools=tools,
    model=model,
)

def chat_fn(message, history):
    return str(agent.run(message))

demo = gr.ChatInterface(
    fn=chat_fn,
    title="Cyber Threat MCP Agent (OpenAI + MCP)",
    description="An OpenAI GPT agent that invokes local MCP tools.",
    examples=[
        "What are the potential mitigations of CWE-413?",
        "What are the consequences of CWE-89?",
    ],
)

if __name__ == "__main__":
    demo.launch()

