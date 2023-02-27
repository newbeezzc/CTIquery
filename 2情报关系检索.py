# coding: utf-8
from pycti import OpenCTIApiClient
import hashlib
from datetime import datetime, date
from collections import defaultdict
import json
from utils import list, parse_ioc_type, parse_object_type


def output_json(file_name):
    # Variables
    api_url = "http://113.54.217.126:4000"
    api_token = "1AD9B432-2E47-2DEE-E4EC-017681B4DF2A"
    # api_url = "http://localhost:4000"
    # api_token = "2f5886e0-47e2-4e1a-955f-5b7df4813588"

    # OpenCTI initialization
    opencti_api_client = OpenCTIApiClient(api_url, api_token)

    # results = list(opencti_api_client, first=100, getAll=False)  # 默认100条，指定数目使用first参数
    from_type = ["Domain-Name", "StixFile", "URL", "Email-Addr", "IPv4-Addr", "IPv6-Addr"]
    to_type = ["Domain-Name", "StixFile", "URL", "Email-Addr", "IPv4-Addr", "IPv6-Addr", "Report", "Malware",
               "Intrusion-Set"]
    results = opencti_api_client.stix_cyber_observable_relationship.list(first=100, getAll=True, fromTypes=from_type,
                                                                         toTypes=to_type)  # 默认100条，指定数目使用first参数
    # 以下为对应字段
    with open(file_name, "w", newline="\n", encoding="utf-8") as Relation_detail:
        Relation_items = []
        for result in results:
            Relation_item = defaultdict(list)
            if result["to"]["entity_type"] == "Malware":
                if not result["to"]["is_family"]:
                    continue  # 如果是恶意软件但不是恶意家族，跳过
            Relation_item["IOC"] = result["from"]["observable_value"]  # IOC值
            Relation_item["IOC_type"] = parse_ioc_type(result["from"]["entity_type"])  # IOC类型
            Relation_item["object_type"] = parse_object_type(result["to"]["entity_type"])  # 对象类型
            Relation_item["value"] = result["to"]["observable_value"] if result["to"][
                                                                             "observable_value"] is not None else \
                result["to"]["id"]  # Value（IOC值，其他存ID）
            if result["from"]["entity_type"] == "StixFile":
                hasMD5 = False
                for hash in result["from"]["hash"]:
                    if hash["algorithm"] == 'MD5':
                        Relation_item["IOC"] = hash["hash"]  # 如果是文件则把MD5作为IOC值
                        hasMD5 = True
                if not hasMD5:  # 如果是文件但没有MD5则跳过
                    continue
            if result["to"]["entity_type"] == "StixFile":
                hasMD5 = False
                for hash in result["from"]["hash"]:
                    if hash["algorithm"] == 'MD5':
                        Relation_item["value"] = hash["hash"]  # 如果是文件则把MD5作为IOC值
                        hasMD5 = True
                if not hasMD5:  # 如果是文件但没有MD5则跳过
                    continue
            Relation_item["relation_type"] = result["relationship_type"]  # relation_type
            Relation_item["relation_order"] = 0  # relation_order

            Relation_items.append(Relation_item)

        Relation_json_str = json.dumps(
            Relation_items, indent=4, ensure_ascii=False
        )
        Relation_detail.write(Relation_json_str + "\n")


if __name__ == "__main__":
    output_json(
        file_name="Relation_Analysis_all.json"
    )
