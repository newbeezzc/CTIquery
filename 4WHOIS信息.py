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

    results = opencti_api_client.stix_cyber_observable.list(types=["Domain-Name"], first=100,
                                                            getAll=False)  # 默认100条，指定数目使用first参数

    # 以下为对应字段
    with open(file_name, "w", newline="\n", encoding="utf-8") as Domain_detail:
        Domain_items = []
        for result in results:
            Domain_item = defaultdict(list)
            Domain_item["domain"] = result["observable_value"]  # 域名
            Domain_item["register_domain_name"] = None # 注册域名
            Domain_item["registrant(people)"] = None  # 注册人
            Domain_item["contact_email"] = None  # 联系邮箱
            Domain_item["contact_number"] = None  # 联系电话
            Domain_item["organization"] = None  # 所属组织
            Domain_item["country/region"] = None  # 国家地区
            Domain_item["registered_address"] = None  # 注册地址
            Domain_item["registration_time"] = None  # 注册时间
            Domain_item["expiration_time"] = None  # 到期时间
            Domain_item["update_time"] = None  # 更新时间
            Domain_item["registrant(company)"] = None  # 注册商
            Domain_item["WHOIS_server"] = None  # WHOIS服务器
            Domain_item["DNS_server"] = None  # DNS服务器
            Domain_item["domain_status"] = None  # 域名状态

            Domain_items.append(Domain_item)

        Domain_json_str = json.dumps(
            Domain_items, indent=4, ensure_ascii=False
        )
        Domain_detail.write(Domain_json_str + "\n")


if __name__ == "__main__":
    output_json(
        file_name="WHOIS_Info_100.json"
    )
