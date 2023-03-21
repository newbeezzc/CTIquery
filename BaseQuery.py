import json

import pandas as pd
import yaml
from pathlib import Path
from pycti import OpenCTIApiClient

from utils import load_label_dict


class QueryParams:
    def __init__(self):
        self.properties = None
        self.types = None
        self.filters = None
        self.first = 100


class BaseQuery:
    def __init__(self):
        config_path = Path(__file__).parent.joinpath("QueryConfig.yml")
        config = (
            yaml.load(config_path.open(), Loader=yaml.SafeLoader)
        )
        # 配置CTI连接
        config_opencti = config["opencti"]
        self.api_url = config_opencti['url']
        self.api_token = config_opencti['token']
        self.client = OpenCTIApiClient(self.api_url, self.api_token)

        config_files = config["files"]
        self.query_file_dic = config_files["query_dic"]
        self.query_file_name = None
        self.output_file_dic = config_files["output_dic"]
        self.output_file_name = None

        self.label_dict = load_label_dict()  # 加载标签映射字典

        # 查询参数
        self.query_params = QueryParams()

        self.query_data = None

    def load_query_data(self):
        if self.query_file_name is not None:
            query_file_path = Path(__file__).parent.joinpath(f"{self.query_file_dic}/{self.query_file_name}")
            df = pd.read_csv(query_file_path, sep=",", header=None)
        else:
            raise ValueError("query_file_name is not defined")
        return df

    def Query(self):
        # 加载需要查询的数据
        self.query_data = self.load_query_data()
        results = list()
        for index, row in self.query_data.iterrows():
            # 每次请求一个数据
            result = self.Request(row.tolist())
            if result:
                results.extend(result)
        json_str = self.Produce(results)
        self.write_json(json_str)

    def Request(self, row_data):
        self.set_query_params(row_data)
        return self.doRequest()

    def doRequest(self):
        raise NotImplementedError

    def Produce(self, results):
        items = []
        for result in results:
            item = self.doProduce(result)
            if item is not None:
                items.append(item)
        json_str = json.dumps(
            items, indent=4, ensure_ascii=False
        )
        return json_str

    def doProduce(self, result):
        raise NotImplementedError

    def write_json(self, json_str):
        if self.output_file_name is not None:
            output_file_path = Path(__file__).parent.joinpath(f"{self.output_file_dic}/{self.output_file_name}")
            with open(output_file_path, "w", newline="\n", encoding="utf-8") as detail:
                detail.write(json_str + "\n")
        else:
            raise ValueError("output_file_name is not defined")

    def set_query_params(self, row_data):
        raise NotImplementedError


if __name__ == "__main__":
    Q = BaseQuery()
    Q.Query()
