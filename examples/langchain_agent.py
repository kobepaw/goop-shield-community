"""LangChain integration: Shield as a callback handler.

Requires:
    pip install goop-shield langchain langchain-openai

Start Shield server first:
    goop-shield serve --port 8787
"""

from goop_shield.adapters.langchain import (
    LangChainShieldAdapter,
    LangChainShieldCallback,
)

# --- Option 1: Direct adapter usage ---


def example_direct_adapter():
    """Use the adapter directly to defend prompts."""
    adapter = LangChainShieldAdapter(
        shield_url="http://localhost:8787",
        api_key=None,  # Set if SHIELD_API_KEY is configured
    )

    # Defend a prompt
    result = adapter.intercept_prompt("What is the capital of France?")
    print(f"Allowed: {result.allowed}")
    print(f"Filtered: {result.filtered_prompt}")

    # Intercept a tool call
    result = adapter.intercept_tool_call("web_search", {"query": "secret data"})
    print(f"Tool allowed: {result.allowed}")

    # Scan a response
    scan = adapter.scan_response("The password is hunter2")
    print(f"Response safe: {scan.safe}")


# --- Option 2: LangChain callback handler ---


def example_callback_handler():
    """Use Shield as a LangChain callback for automatic interception.

    This example shows the callback setup. Requires a real LLM provider
    to run end-to-end.
    """
    callback = LangChainShieldCallback(
        shield_url="http://localhost:8787",
    )

    # In a real setup, attach to your chain:
    #
    # from langchain_openai import ChatOpenAI
    # from langchain.chains import LLMChain
    # from langchain.prompts import PromptTemplate
    #
    # llm = ChatOpenAI(model="gpt-4")
    # prompt = PromptTemplate.from_template("Answer: {question}")
    # chain = LLMChain(llm=llm, prompt=prompt, callbacks=[callback])
    #
    # result = chain.run(question="What is 2+2?")
    # # Shield automatically:
    # #   1. Defends the prompt via on_llm_start
    # #   2. Scans the response via on_llm_end
    # #   3. Intercepts tool calls via on_tool_start

    print("LangChain callback handler configured.")
    print("Attach to your chain with: chain = LLMChain(..., callbacks=[callback])")
    print(f"Shield URL: {callback._adapter._http._url}")


if __name__ == "__main__":
    print("=== Direct Adapter ===")
    example_direct_adapter()
    print()
    print("=== Callback Handler ===")
    example_callback_handler()
