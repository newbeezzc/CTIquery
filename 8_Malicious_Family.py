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
            filters=self.query_params.filters,
            customAttributes=self.query_params.properties
        )

    def doProduce(self, result):
        item = dict()
        item["malware_id"] = result.get("id")  # 家族唯一ID
        item["malware_name"] = result.get("name")  # 家族名称
        item["internal_number"] = None  # 内部编号（空值）
        item["family_description"] = result.get("description")  # 家族介绍
        item["discover_time"] = parse_date(result.get("first_seen"))  # 发现时间
        item["aliases"] = result.get("aliases")  # 别名

        note = result.get("notes", [])
        attack_impact = None
        communication_ways = None
        features = None
        malicious_type = None
        if note:
            note_content = note[0].get("content")
            if note_content is not None:
                note_content_js = json.loads(note_content[note_content.index('{'):])
                attack_impact = note_content_js.get("attack_impact")
                malicious_type = note_content_js.get("malicious_type")
                communication_ways = note_content_js.get("communication_ways")
                features = note_content_js.get("features")
        item["attack_impact"] = attack_impact  # 攻击影响
        item["communication_ways"] = communication_ways  # 传播方式
        item["features"] = features  # 特点
        item["threat_type"] = result.get("malware_types") or malicious_type  # 威胁类型

        item["impact_platform"] = result.get("architecture_execution_envs")  # 影响平台 是不是这个字段
        references = [ref.get("url") for ref in result.get("externalReferences", [])]
        item["reference_link"] = references  # 参考链接

        relations = result.get("stixCoreRelationships", [])
        COA = None
        for relation in relations:
            relation_type = relation.get("relationship_type")
            if relation_type == "mitigates":
                COA = relation.get("from", {}).get("description")

        item["disposal_suggestions"] = COA  # 处置建议

        return [item]

    def set_query_params(self, row_data):
        self.query_params.properties = properties.MaliciousFamily_properties
        self.query_params.filters = [{"key": "name", "values": row_data[0]}]


if __name__ == "__main__":
    # s = "CN360{\n    \"attack_impact\": \"无\",\n    \"malicious_type\": \"其他远控\",\n    \"communication_ways\": [],\n    \"features\": []\n}"
    # js = json.loads(s[s.index('{'):])

    q = MaliciousFamilyQuery()
    q.Query()
