# coding: utf-8
import json
import re

from BaseQuery import BaseQuery
from utils import parse_date, get_all_country_CHN, is_chinese_string, parse_source_category, cast_label, trans_timezone
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
        item["report_id"] = result.get("id")  # 报告唯一ID
        item["title"] = result.get("name")  # 标题
        item["author"] = result.get("createdBy", {}).get("name")  # 作者
        item["report_time"] = parse_date(result.get("published"))  # 报告时间
        item["description"] = result.get("description")  # 内容简介
        import_files = result.get("importFiles", [])
        item["content"] = import_files[0].get("name") if import_files else None  # 内容
        external_references = result.get("externalReferences")
        item["original_link"] = external_references[0].get("url") if external_references else None  # 原文链接

        int_types, labels = cast_label(result.get("objectLabel"), self.label_dict)
        item["intelligence_type"] = int_types  # 情报类型
        item["label"] = labels  # 情报标签
        item["source"] = "UESTC"  # 情报来源（电子科大）
        item["source_category"] = parse_source_category(
            result.get("report_types")[0])  # 来源分类（公众号 / 技术博客 / 社交媒体 / 厂商情报订阅）

        attack_industry = []
        organization = []
        target_area = []
        relate_ioc = []
        for obj in result["objects"]:
            obj_type = obj["entity_type"]
            if obj_type == "Sector":  # 攻击行业
                attack_industry.append(obj["name"])
            elif obj_type == "Intrusion-Set":  # 涉及组织
                organization.append(obj["name"])
            elif obj_type == "Country" or obj_type == "City":  # 攻击国家/地区
                target_area.append(obj["name"])
            elif obj_type == "Domain-Name":  # 域名
                ioc = self.client.stix_cyber_observable.read(id=obj["id"])["observable_value"]
                relate_ioc.append({"ioc": ioc, "ioc_type": "ioc_domain"})
            elif obj_type == "StixFile":
                ioc = self.client.stix_cyber_observable.read(id=obj["id"])["observable_value"]
                relate_ioc.append({"ioc": ioc, "ioc_type": "ioc_md5"})
            elif obj_type == "Url":
                ioc = self.client.stix_cyber_observable.read(id=obj["id"])["observable_value"]
                relate_ioc.append({"ioc": ioc, "ioc_type": "ioc_url"})
            elif obj_type == "Email-Addr":
                ioc = self.client.stix_cyber_observable.read(id=obj["id"])["observable_value"]
                relate_ioc.append({"ioc": ioc, "ioc_type": "ioc_mail"})
            elif obj_type == "IPv4-Addr":
                ioc = self.client.stix_cyber_observable.read(id=obj["id"])["observable_value"]
                relate_ioc.append({"ioc": ioc, "ioc_type": "ioc_ipv4"})
            elif obj_type == "IPv6-Addr":
                ioc = self.client.stix_cyber_observable.read(id=obj["id"])["observable_value"]
                relate_ioc.append({"ioc": ioc, "ioc_type": "ioc_ipv6"})
        item["attack_industry"] = attack_industry  # 攻击行业
        item["organization"] = organization  # 涉及组织
        item["target_area"] = target_area  # 攻击国家/地区
        item["download_link"] = item.get("original_link")  # 下载链接，同源链接
        item["sharing_scope"] = 0  # 共享范围(0 全部)
        item["shared_industry"] = None  # 共享行业（空值）
        item["relate_ioc"] = relate_ioc  # 关联ioc

        return [item]

    def set_query_params(self, row_data):
        date_begin, date_end = trans_timezone(row_data[0])
        self.query_params.filters = [
            {"key": "published", "values": [date_begin], "operator": "gt"},
            {"key": "published", "values": [date_end], "operator": "lt"}
        ]


if __name__ == "__main__":
    # print(trans_timezone("2023-2-25"))
    q = ReportQuery()
    q.Query()
