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
                                              getAll=False)  # 默认100条，指定数目使用first参数

    # 以下为对应字段
    with open(file_name, "w", newline="\n", encoding="utf-8") as malware_detail:
        malware_items = []
        for result in results:
            malware_item = defaultdict(list)
            malware_item["malware_id"] = result["id"]  # 家族唯一ID
            malware_item["malware_name"] = result["name"]  # 家族名称
            malware_item["internal_number"] = None  # 内部编号（空值）
            malware_item["family_description"] = result["description"]  # 家族介绍
            malware_item["discover_time"] = parse_date(result["first_seen"])  # 发现时间
            malware_item["aliases"] = result["aliases"]  # 别名
            malware_item["attack_impact"] = None  # 攻击影响
            malware_item["propagation_mode"] = None  # 传播方式
            malware_item["characteristic"] = None  # 特点
            malware_item["threat_type"] = result["malware_types"]  # 威胁类型
            malware_item["impact_platform"] = result["architecture_execution_envs"]  # 影响平台 是不是这个字段
            references = []
            for re in result["externalReferences"]:
                references.append(re["url"])
            malware_item["reference_link"] = references  # 参考链接
            malware_item["disposal_suggestions"] = None  # 处置建议

            malware_items.append(malware_item)

        malware_json_str = json.dumps(
            malware_items, indent=4, ensure_ascii=False
        )
        malware_detail.write(malware_json_str + "\n")


if __name__ == "__main__":
    output_json(
        file_name="malware_100.json"
    )
