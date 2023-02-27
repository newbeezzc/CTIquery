# coding: utf-8
from pycti import OpenCTIApiClient
import hashlib
from datetime import datetime, date
from collections import defaultdict
import json


def output_json(file_name):
    # Variables
    # api_url = "http://113.54.217.126:4000"
    # api_token = "1AD9B432-2E47-2DEE-E4EC-017681B4DF2A"
    api_url = "http://localhost:4000"
    api_token = "2f5886e0-47e2-4e1a-955f-5b7df4813588"

    # OpenCTI initialization
    opencti_api_client = OpenCTIApiClient(api_url, api_token)

    results = opencti_api_client.stix_cyber_observable.list(types=["IPv4-Addr", "IPv6-Addr"], first=100,
                                                            getAll=False)  # 默认100条，指定数目使用first参数

    # 以下为对应字段
    with open(file_name, "w", newline="\n", encoding="utf-8") as IP_detail:
        IP_items = []
        for result in results:
            IP_item = defaultdict(list)
            IP_item["IP"] = result["observable_value"]  # IP
            IP_item["IP_type"] = result["entity_type"]  # IP类型
            IP_item["port"] = None  # 端口
            IP_item["web_title"] = None  # 网页标题
            IP_item["web_content"] = None  # 网页内容
            IP_item["banner_version"] = None  # banner 软件信息版本

            IP_items.append(IP_item)

        IP_json_str = json.dumps(
            IP_items, indent=4, ensure_ascii=False
        )
        IP_detail.write(IP_json_str + "\n")


# md5_id1 = hashlib.md5("my IP".encode(encoding="UTF-8")).hexdigest()#MD5的id生成
if __name__ == "__main__":
    output_json(
        file_name="IP_port_100.json"
    )
