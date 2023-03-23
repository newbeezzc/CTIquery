# coding: utf-8
from BaseQuery import BaseQuery
from utils import parse_date, parse_ioc_type, cast_label, reverse_ioc_type, parse_object_type
import properties


class IOCRelationQuery(BaseQuery):
    def __init__(self):
        super().__init__()
        self.query_file_name = "IOCRelation_text.csv"
        self.output_file_name = "intelligence_relation_analysis.json"

    def doRequest(self):
        """
        直接查StixCyberObservable，从其中的stixCoreRelationships和stixCyberObservableRelationships字段获取内容。
        :return: 查询CTI的结果
        """
        return self.client.stix_cyber_observable.list(
            filters=self.query_params.filters,
            customAttributes=self.query_params.properties,
            types=self.query_params.types
        )

    def doProduce(self, result):
        items = list()
        ioc = result.get("observable_value")
        core_relations = result.get("stixCoreRelationships", [])
        cyber_observable_relations = result.get("stixCyberObservableRelationships", [])
        core_relations = core_relations if core_relations is not None else []
        cyber_observable_relations = cyber_observable_relations if cyber_observable_relations is not None else []
        relations = core_relations + cyber_observable_relations

        if relations:
            for relation in relations:
                item = self.produce_relationship(relation, ioc)
                if item:
                    items.append(item)
        return items

    def produce_relationship(self, relation, ioc_value):
        item = dict()
        types = ["Domain-Name", "StixFile", "URL", "Email-Addr", "IPv4-Addr", "IPv6-Addr", "Report", "Malware",
                 "Intrusion-Set"]
        from_obj = relation.get("from", {})
        to_obj = relation.get("to", {})
        from_type = from_obj.get("entity_type")
        to_type = to_obj.get("entity_type")
        if any(t is None or t not in types for t in [from_type, to_type]):
            return {}  # 如果关系的任何一端不属于需求的类型则直接跳过

        # 判断关系的两端，哪一端才是查询的ioc
        ioc = obj = relation_order = None
        if from_obj.get("observable_value") == ioc_value:
            ioc = from_obj
            obj = to_obj
            relation_order = 0
        elif to_obj.get("observable_value") == ioc_value:
            ioc = to_obj
            obj = from_obj
            relation_order = 1

        ioc_type = ioc.get("entity_type")
        object_type = obj.get("entity_type")
        if object_type == "Malware":
            if not obj.get("is_family"):
                return {}  # 如果是恶意软件但不是恶意家族，跳过

        item["ioc"] = ioc.get("observable_value")  # IOC值
        item["ioc_type"] = parse_ioc_type(ioc_type)  # IOC类型
        item["object_type"] = parse_object_type(object_type)  # 对象类型
        value = obj.get("observable_value", obj.get("name"))
        item["value"] = value if value is not None else obj.get("id")  # Value（IOC值，其他存ID）
        if ioc_type == "StixFile":
            hasMD5 = False
            for hash in ioc.get("hash", []):
                if hash.get("algorithm") == 'MD5':
                    item["ioc"] = hash.get("hash")  # 如果是文件则把MD5作为IOC值
                    hasMD5 = True
            if not hasMD5:  # 如果是文件但没有MD5则跳过
                return {}
        if object_type == "StixFile":
            hasMD5 = False
            for hash in obj.get("hash", []):
                if hash.get("algorithm") == 'MD5':
                    item["value"] = hash.get("hash")  # 如果是文件则把MD5作为IOC值
                    hasMD5 = True
            if not hasMD5:  # 如果是文件但没有MD5则跳过
                return {}
        item["relation_type"] = relation.get("relationship_type")  # relation_type
        item["relation_order"] = relation_order  # relation_order 关系方向:0-使用(指向外);1-被使用(指向内
        return item

    def set_query_params(self, row_data):
        self.query_params.properties = properties.IOCRelation_properties
        self.query_params.types = ["Domain-Name", "StixFile", "URL", "Email-Addr", "IPv4-Addr", "IPv6-Addr"]
        filters = [
            {"key": "value", "values": [row_data[0]]},
            {"key": "entity_type", "values": [reverse_ioc_type(row_data[1])]}
        ]
        self.query_params.filters = filters


if __name__ == "__main__":
    # output_json(
    #     query_file_name="查询文本demo/IOC_text.csv",
    #     output_file_name="intelligence_evaluation_100.json"
    # )
    query = IOCRelationQuery()
    query.Query()
