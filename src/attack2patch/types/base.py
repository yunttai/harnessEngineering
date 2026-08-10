from pydantic import BaseModel, ConfigDict


class StrictModel(BaseModel):
    """Base model for data crossing a trust boundary."""

    model_config = ConfigDict(extra="forbid")
