# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "http://113.54.217.126:4000"
api_token = "1AD9B432-2E47-2DEE-E4EC-017681B4DF2A"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Get all reports using the pagination
custom_attributes = """
    id
    relationship_type
"""

final_reports = []
data = {"pagination": {"hasNextPage": True, "endCursor": None}}
while data["pagination"]["hasNextPage"]:
    after = data["pagination"]["endCursor"]
    if after:
        print("Listing reports after " + after)
    data = opencti_api_client.stix_core_relationship.list(
        first=50,
        after=after,
        customAttributes=custom_attributes,
        withPagination=True,
        orderBy="created_at",
        orderMode="asc",
    )
    final_reports = final_reports + data["entities"]

# Print
for report in final_reports:
    print("[" + report["published"] + "] " + report["name"])