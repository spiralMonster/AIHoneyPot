import os
from dotenv import load_dotenv
from langchain.prompts import ChatPromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI
from RequestClassifier.context_from_internet import ContextFromInternet
from RequestClassifier.response_from_url import ResponseFromURL
from RequestClassifier.honeypot_specs import HoneyPotSpecs
load_dotenv()


def HoneyPot(context_from_home_network,context_from_internet):
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.0-flash-001",
        temperature=0,
        max_tokens=None,
        timeout=None,
        max_retries=2,
        api_key=os.environ["GEMINI_API_KEY"]
    ).with_structured_output(HoneyPotSpecs)

    template="""
    You are a HoneyPot.
    Your job is to deceive the Cyber attackers by generating such response that will make them feel that they are in contact with real server.
    Generate such responses that will engage the attackers more.
    Use the following context of how servers on the internet and the server on home network respond in order to generate your response.
    
    Response from servers on Internet:
    {response_internet}
    
    Response from server on Home Network:
    {response_home}
    
    """

    prompt=ChatPromptTemplate.from_template(template=template,input_variable=["response_internet","response_home"])

    honeypot_chain=prompt|llm

    resp=honeypot_chain.invoke(
        {
            "response_internet":context_from_internet,
            "response_home":context_from_home_network
        }
    )

    result={
        "server_response":resp.server_response,
        "explanation":resp.explanation
    }

    return result

if __name__=="__main__":
    context_from_internet=ContextFromInternet(payload_data="/api/file")
    context_from_home=ResponseFromURL(url="http://priyanshu23.pythonanywhere.com/api/file",request_type="harmful")
    print(HoneyPot(context_from_home_network=context_from_home,context_from_internet=context_from_internet))
