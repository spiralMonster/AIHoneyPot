from pydantic import BaseModel,Field

class HoneyPotSpecs(BaseModel):
    server_response:str=Field("Mimic server response to lure attacker")
    explanation:str=Field("Why do you think that the given response will lure attacker")