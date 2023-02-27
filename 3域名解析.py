# coding: utf-8
from pycti import OpenCTIApiClient
import hashlib
from datetime import datetime, date
from collections import defaultdict
import json
from utils import list, parse_date


def output_json(file_name):
    # Variables
    api_url = "http://113.54.217.126:4000"
    api_token = "1AD9B432-2E47-2DEE-E4EC-017681B4DF2A"
    # api_url = "http://localhost:4000"
    # api_token = "2f5886e0-47e2-4e1a-955f-5b7df4813588"

    # OpenCTI initialization
    opencti_api_client = OpenCTIApiClient(api_url, api_token)

    # results = list(opencti_api_client, relationship_type="resolves-to", first=100, getAll=False)  # 默认100条，指定数目使用first参数
    results = opencti_api_client.stix_cyber_observable_relationship.list(first=100, getAll=False, relationship_type="resolves-to")  # 默认100条，指定数目使用first参数

    # 以下为对应字段
    with open(file_name, "w", newline="\n", encoding="utf-8") as Domain_detail:
        Domain_items = []
        for result in results:
            Domain_item = defaultdict(list)
            Domain_item["domain"] = result["from"]["observable_value"]  # 域名
            Domain_item["analysis_type"] = None  # 解析类型
            Domain_item["discovery_time"] = parse_date(result["created_at"])  # 发现 时间-默认为1970
            Domain_item["analytic_value"] = result["to"]["observable_value"]   # 解析值
            Domain_item["last_seen"] = parse_date(result["update_at"])  # 最近发现时间


            Domain_items.append(Domain_item)

        Domain_json_str = json.dumps(
            Domain_items, indent=4, ensure_ascii=False
        )
        Domain_detail.write(Domain_json_str + "\n")


if __name__ == "__main__":
    output_json(
        file_name="Domain_Analysis_100.json"
    )
