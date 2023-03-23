# coding: utf-8
import json
import re

from BaseQuery import BaseQuery
from utils import parse_date, get_all_country_CHN, is_chinese_string, parse_source_category, cast_label
import properties


class ReportQuery(BaseQuery):
    def __init__(self):
        super().__init__()
        self.query_file_name = "Report_text.csv"
        self.output_file_name = "report.json"

    def doRequest(self):
        """
        请求CTI，返回结果。
        :return: 查询CTI的结果
        """
        return self.client.report.list(
            filters=self.query_params.filters
        )

    def doProduce(self, result):
        item = dict()
        item["report_id"] = result["id"]  # 报告唯一ID
        item["title"] = result["name"]  # 标题
        try:
            item["author"] = result["createdBy"]["name"]  # 作者
        except:
            item["author"] = None
        item["report_time"] = parse_date(result["published"])  # 报告时间
        item["description"] = result["description"]  # 内容简介
        try:
            item["content"] = result["importFiles"][0]["name"]  # 内容
        except:
            item["content"] = None
        try:
            item["original_link"] = result["externalReferences"][0]["url"]  # 原文链接
        except:
            item["original_link"] = None

        int_types, labels = cast_label(result["objectLabel"], label_dict)
        item["intelligence_type"] = int_types  # 情报类型
        item["label"] = labels  # 情报标签
        item["source"] = "UESTC"  # 情报来源（电子科大）
        try:
            item["source_category"] = parse_source_category(
                result["report_types"][0])  # 来源分类（公众号 / 技术博客 / 社交媒体 / 厂商情报订阅）
        except:
            item["source_category"] = None
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
        item["attack_industry"] = attack_industry  # 攻击行业
        item["organization"] = organization  # 涉及组织
        item["target_area"] = target_area  # 攻击国家/地区
        item["download_link"] = item["original_link"]  # 下载链接，同源链接
        item["sharing_scope"] = 0  # 共享范围(0 全部)
        item["shared_industry"] = None  # 共享行业（空值）
        item["relate_ioc"] = relate_ioc  # 关联ioc

        return [item]

    def set_query_params(self, row_data):
        self.query_params.filters = [{"key": "published_day", "values": row_data[0]}]


if __name__ == "__main__":
    q = ReportQuery()
    q.Query()
