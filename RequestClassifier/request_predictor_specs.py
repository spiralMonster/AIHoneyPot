from pydantic import BaseModel,Field
from typing_extensions import Literal

class RequestPredictorSpecs(BaseModel):
    request_type:Literal["normal","harmful"]=Field(description="You have to decide whether the request made to server is normal or harmful")
    explanation:str=Field("Why do you think whether the request is normal or harmful?")
    attack_type:Literal["SYN-Flooding","UDP-Flooding","ICMP-Flooding","HTTP-Flooding","Fragmentation-Attack","Slowris-Attack","None"]=Field("Decide the type of attack.")
