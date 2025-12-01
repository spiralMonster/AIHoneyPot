import os
from dotenv import load_dotenv
from langchain.prompts import ChatPromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI
from RequestClassifier.request_predictor_specs import RequestPredictorSpecs
from RequestClassifier.extracting_features_from_packet import extract_features

load_dotenv()


def RequestPredictor(features):
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.0-flash-001",
        temperature=0,
        max_tokens=None,
        timeout=None,
        max_retries=2,
        api_key=os.environ["GEMINI_API_KEY"]
    ).with_structured_output(RequestPredictorSpecs)

    template = """
    You are given with the various features extracted during the communication between the client and server.
    Your job is to decide whether the request is harmful or normal along with explanation and the type of attack
    Note: 
    *Keep the explanation short and crisp.
    *If the request is normal then provide attack has None.

    Extracted Features:
    {features}
    """

    prompt = ChatPromptTemplate.from_template(template=template, input_variable=['features'])
    request_predictor_chain =prompt|llm

    response = request_predictor_chain.invoke({"features": features})

    result = {
        "request_type": response.request_type,
        "attack":response.attack_type,
        "explanation": response.explanation
    }

    return result


if __name__== "__main__":
    features = extract_features(pcap_file="analysis.pcap")
    print(f"Extracted features: {features}")
    result = RequestPredictor(features)
    print(f"Result:{result}")