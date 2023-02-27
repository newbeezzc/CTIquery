# coding: utf-8
from pycti import OpenCTIApiClient
import hashlib
from datetime import datetime, date
from collections import defaultdict
import json
from utils import parse_date, parse_source_category, load_label_dict, cast_label


def output_json(file_name):
    # Variables
    api_url = "http://113.54.217.126:4000"
    api_token = "1AD9B432-2E47-2DEE-E4EC-017681B4DF2A"
    # api_url = "http://localhost:4000"
    # api_token = "2f5886e0-47e2-4e1a-955f-5b7df4813588"

    # OpenCTI initialization
    opencti_api_client = OpenCTIApiClient(api_url, api_token)

    results = opencti_api_client.report.list(first=100, getAll=False)  # 默认100条，指定数目使用first参数

    label_dict = load_label_dict()  # 加载标签映射字典
    # results = opencti_api_client.report.read(id="report--25331a9b-8d01-5859-b913-8b6b1ba0efc9") #根据id读取特定行
    # 以下为对应字段
    with open(file_name, "w", newline="\n", encoding="utf-8") as report_detail:
        report_items = []
        for result in results:
            report_item = defaultdict(list)
            report_item["report_id"] = result["id"]  # 报告唯一ID
            report_item["title"] = result["name"]  # 标题
            try:
                report_item["author"] = result["createdBy"]["name"]  # 作者
            except:
                report_item["author"] = None
            report_item["report_time"] = parse_date(result["published"])  # 报告时间
            report_item["description"] = result["description"]  # 内容简介
            try:
                report_item["content"] = result["importFiles"][0]["name"]  # 内容
            except:
                report_item["content"] = None
            try:
                report_item["original_link"] = result["externalReferences"][0]["url"]  # 原文链接
            except:
                report_item["original_link"] = None

            int_types, labels = cast_label(result["objectLabel"], label_dict)
            report_item["intelligence_type"] = int_types  # 情报类型
            report_item["label"] = labels  # 情报标签
            report_item["source"] = "UESTC"  # 情报来源（电子科大）
            try:
                report_item["source_category"] = parse_source_category(
                    result["report_types"][0])  # 来源分类（公众号 / 技术博客 / 社交媒体 / 厂商情报订阅）
            except:
                report_item["source_category"] = None
            attack_industry = []
            organization = []
            target_area = []
            relate_ioc = []
            for object in result["objects"]:
                # print(object["entity_type"])
                if object["entity_type"] == "Sector":  # 攻击行业
                    attack_industry.append(object["name"])
                if object["entity_type"] == "Intrusion-Set":  # 涉及组织
                    organization.append(object["name"])
                if object["entity_type"] == "Country" or object["entity_type"] == "City":  # 攻击国家/地区
                    target_area.append(object["name"])
                if object["entity_type"] == "Domain-Name":  # 域名
                    ioc = opencti_api_client.stix_cyber_observable.read(id=object["id"])["observable_value"]
                    relate_ioc.append({"ioc": ioc, "ioc_type": "ioc_domain"})
                if object["entity_type"] == "StixFile":
                    ioc = opencti_api_client.stix_cyber_observable.read(id=object["id"])["observable_value"]
                    relate_ioc.append({"ioc": ioc, "ioc_type": "ioc_md5"})
                if object["entity_type"] == "Url":
                    ioc = opencti_api_client.stix_cyber_observable.read(id=object["id"])["observable_value"]
                    relate_ioc.append({"ioc": ioc, "ioc_type": "ioc_url"})
                if object["entity_type"] == "Email-Addr":
                    ioc = opencti_api_client.stix_cyber_observable.read(id=object["id"])["observable_value"]
                    relate_ioc.append({"ioc": ioc, "ioc_type": "ioc_mail"})
                if object["entity_type"] == "IPv4-Addr":
                    ioc = opencti_api_client.stix_cyber_observable.read(id=object["id"])["observable_value"]
                    relate_ioc.append({"ioc": ioc, "ioc_type": "ioc_ipv4"})
                if object["entity_type"] == "IPv6-Addr":
                    ioc = opencti_api_client.stix_cyber_observable.read(id=object["id"])["observable_value"]
                    relate_ioc.append({"ioc": ioc, "ioc_type": "ioc_ipv6"})
            report_item["attack_industry"] = attack_industry  # 攻击行业
            report_item["organization"] = organization  # 涉及组织
            report_item["target_area"] = target_area  # 攻击国家/地区
            report_item["download_link"] = report_item["original_link"]  # 下载链接，同源链接
            report_item["sharing_scope"] = 0  # 共享范围(0 全部)
            report_item["shared_industry"] = None  # 共享行业（空值）
            report_item["relate_ioc"] = relate_ioc  # 关联ioc

            report_items.append(report_item)

        report_json_str = json.dumps(
            report_items, indent=4, ensure_ascii=False
        )
        report_detail.write(report_json_str + "\n")


if __name__ == "__main__":
    output_json(
        file_name="report_100.json"
    )
