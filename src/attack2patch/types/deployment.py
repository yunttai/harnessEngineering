from pydantic import BaseModel


class Deployment(BaseModel):
    patch_id: str
    previous_image: str
    candidate_image: str
    status: str = "BUILDING"
