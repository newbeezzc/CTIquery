# coding: utf-8
from pycti import OpenCTIApiClient
import hashlib
from datetime import datetime, date
from collections import defaultdict
import json
from utils import parse_date


def output_json(file_name):
    # Variables
    # api_url = "http://113.54.217.126:4000"
    # api_token = "1AD9B432-2E47-2DEE-E4EC-017681B4DF2A"
    api_url = "http://localhost:4000"
    api_token = "2f5886e0-47e2-4e1a-955f-5b7df4813588"

    # OpenCTI initialization
    opencti_api_client = OpenCTIApiClient(api_url, api_token)

    properties = """
        id
        name
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
                    to {
                        ... on Location {
                            id
                            standard_id
                            entity_type
                            name
                        }
                        ... on Identity  {
                            id
                            standard_id
                            entity_type
                            name
                        }     
                        ... on AttackPattern  {
                            id
                            standard_id
                            entity_type
                            name
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
        description
        aliases
        first_seen
        last_seen
        goals
        resource_level
        primary_motivation
        secondary_motivations
        lang
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
    filter = [{"key": "name", "values": "admin@338", "filterMode": "and"}]
    results = opencti_api_client.intrusion_set.list(first=180, getAll=False, customAttributes=properties)  # 默认100条，指定数目使用first参数

    # 以下为对应字段
    with open(file_name, "w", newline="\n", encoding="utf-8") as organization_detail:
        organization_items = []
        for result in results:
            organization_item = defaultdict(list)
            organization_item["organization_id"] = result["id"]  # 组织唯一ID
            organization_item["organization_name"] = result["name"]  # 组织名称
            organization_item["internal_number"] = None  # 内部编号（空值）
            organization_item["aliases"] = result["aliases"]  # 别名
            organization_item["organization_introduction"] = result["description"]  # 组织介绍
            organization_item["organization_type"] = result["resource_level"]  # 组织类型
            organization_item["discovery_time"] = parse_date(result["first_seen"])  # 发现时间
            organization_item["last_active_time"] = parse_date(result["last_seen"])  # 最近活跃时间
            locations = []
            industry = []
            country = []
            pattern = []
            if result["stixCoreRelationships"] != []:
                for relation in result["stixCoreRelationships"]:
                    relation_type = relation["relationship_type"]
                    if relation["to"] == {}:
                        continue
                    to_entity_type = relation["to"]["entity_type"]
                    if relation_type == "originates-from":
                        locations.append(relation["to"]["name"])
                    elif relation_type == "targets":
                        if to_entity_type == "Sector":
                            industry.append(relation["to"]["name"])
                        elif to_entity_type == "Country":
                            country.append(relation["to"]["name"])
                    elif relation_type == "uses":
                        if to_entity_type == "Attack-Pattern":
                            pattern.append(relation["to"]["name"])

            organization_item["organization_location"] = locations  # 组织位置
            organization_item["target_industry"] = industry  # 目标行业
            organization_item["target_countries/regions"] = country  # 目标国家、地区
            organization_item["language"] = result["lang"]  # 常用语言
            organization_item["source"] = "爬虫"  # 情报来源(爬虫) result["createdBy"]
            organization_item["attack_mode"] = pattern  # 攻击方式

            organization_items.append(organization_item)

        organization_json_str = json.dumps(
            organization_items, indent=4, ensure_ascii=False
        )
        organization_detail.write(organization_json_str + "\n")


if __name__ == "__main__":
    output_json(
        file_name="organization_180.json"
    )
