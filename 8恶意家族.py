# coding: utf-8
from pycti import OpenCTIApiClient
import hashlib
from datetime import datetime, date
from collections import defaultdict
import json
from utils import parse_date


def output_json(file_name):
    # Variables
    api_url = "http://113.54.217.126:4000"
    api_token = "1AD9B432-2E47-2DEE-E4EC-017681B4DF2A"
    # api_url = "http://localhost:4000"
    # api_token = "2f5886e0-47e2-4e1a-955f-5b7df4813588"

    # OpenCTI initialization
    opencti_api_client = OpenCTIApiClient(api_url, api_token)
    properties = """
        id
        standard_id
        entity_type
        parent_types
        spec_version
        created_at
        updated_at
        createdBy {
            ... on Identity {
                id
                standard_id
                entity_type
                parent_types
                spec_version
                identity_class
                name
                description
                roles
                contact_information
                x_opencti_aliases
                created
                modified
                objectLabel {
                    edges {
                        node {
                            id
                            value
                            color
                        }
                    }
                }
            }
            ... on Organization {
                x_opencti_organization_type
                x_opencti_reliability
            }
            ... on Individual {
                x_opencti_firstname
                x_opencti_lastname
            }
        }
        objectMarking {
            edges {
                node {
                    id
                    standard_id
                    entity_type
                    definition_type
                    definition
                    created
                    modified
                    x_opencti_order
                    x_opencti_color
                }
            }
        }
        objectLabel {
            edges {
                node {
                    id
                    value
                    color
                }
            }
        }
        externalReferences {
            edges {
                node {
                    id
                    standard_id
                    entity_type
                    source_name
                    description
                    url
                    hash
                    external_id
                    created
                    modified
                    importFiles {
                        edges {
                            node {
                                id
                                name
                                size
                                metaData {
                                    mimetype
                                    version
                                }
                            }
                        }
                    }
                }
            }
        }
        stixCoreRelationships {
            edges {
                node {
                    id
                    standard_id
                    entity_type
                    from {
                        ... on Malware {
                            id
                            standard_id
                            entity_type
                            name
                        }
                    }
                    to {
                        ... on Sector {
                            id
                            standard_id
                            entity_type
                            observable_value
                            number
                        }
                        ... on Location {
                            id
                            standard_id
                            entity_type
                            name
                            latitude
                            longitude
                        }                                            
                    }
                    relationship_type
                }
            }
        }
        revoked
        confidence
        created
        modified
        name
        description
        aliases
        malware_types
        is_family
        first_seen
        last_seen
        architecture_execution_envs
        implementation_languages
        capabilities
        killChainPhases {
            edges {
                node {
                    id
                    standard_id
                    entity_type
                    kill_chain_name
                    phase_name
                    x_opencti_order
                    created
                    modified
                }
            }
        }
        importFiles {
            edges {
                node {
                    id
                    name
                    size
                    metaData {
                        mimetype
                        version
                    }
                }
            }
        }
    """

    filter = [{"key": "is_family", "values": "true", "filterMode": "and"}]
    results = opencti_api_client.malware.list(filters=filter, first=100,
                                              getAll=False)  # ??????100????????????????????????first??????

    # ?????????????????????
    with open(file_name, "w", newline="\n", encoding="utf-8") as malware_detail:
        malware_items = []
        for result in results:
            malware_item = defaultdict(list)
            malware_item["malware_id"] = result["id"]  # ????????????ID
            malware_item["malware_name"] = result["name"]  # ????????????
            malware_item["internal_number"] = None  # ????????????????????????
            malware_item["family_description"] = result["description"]  # ????????????
            malware_item["discover_time"] = parse_date(result["first_seen"])  # ????????????
            malware_item["aliases"] = result["aliases"]  # ??????
            malware_item["attack_impact"] = None  # ????????????
            malware_item["propagation_mode"] = None  # ????????????
            malware_item["characteristic"] = None  # ??????
            malware_item["threat_type"] = result["malware_types"]  # ????????????
            malware_item["impact_platform"] = result["architecture_execution_envs"]  # ???????????? ?????????????????????
            references = []
            for re in result["externalReferences"]:
                references.append(re["url"])
            malware_item["reference_link"] = references  # ????????????
            malware_item["disposal_suggestions"] = None  # ????????????

            malware_items.append(malware_item)

        malware_json_str = json.dumps(
            malware_items, indent=4, ensure_ascii=False
        )
        malware_detail.write(malware_json_str + "\n")


if __name__ == "__main__":
    output_json(
        file_name="malware_100.json"
    )
