# coding: utf-8
import json
import re

from BaseQuery import BaseQuery
from utils import parse_date, get_all_country_CHN, is_chinese_string
import properties


class MaliciousFamilyQuery(BaseQuery):
    def __init__(self):
        super().__init__()
        self.query_file_name = "MaliciousFamily_text.csv"
        self.output_file_name = "malicious_family.json"

    def doRequest(self):
        """
        请求CTI，返回结果。
        :return: 查询CTI的结果
        """
        return self.client.malware.list(
            filters=self.query_params.filters
        )

    def doProduce(self, result):
        item = dict()
        item["malware_id"] = result.get("id")  # 家族唯一ID
        item["malware_name"] = result.get("name")  # 家族名称
        item["internal_number"] = None  # 内部编号（空值）
        item["family_description"] = result.get("description")  # 家族介绍
        item["discover_time"] = parse_date(result.get("first_seen"))  # 发现时间
        item["aliases"] = result.get("aliases")  # 别名
        item["attack_impact"] = None  # 攻击影响
        item["propagation_mode"] = None  # 传播方式
        item["characteristic"] = None  # 特点
        item["threat_type"] = result.get("malware_types")  # 威胁类型
        item["impact_platform"] = result.get("architecture_execution_envs")  # 影响平台 是不是这个字段
        references = [ref.get("url") for ref in result.get("externalReferences", [])]
        item["reference_link"] = references  # 参考链接
        item["disposal_suggestions"] = None  # 处置建议

        return [item]

    def set_query_params(self, row_data):
        self.query_params.filters = [{"key": "name", "values": row_data[0]}]


if __name__ == "__main__":
    q = MaliciousFamilyQuery()
    q.Query()
