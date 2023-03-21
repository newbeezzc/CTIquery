"""
生成测试所用数据
"""
import ujson
import pandas as pd


def gen_IOC(filename):
    json_path = "数据查询反馈及示例/"
    IOC_json = "1_intelligence_evaluation_100.json"
    output_datas = []

    with open(json_path + IOC_json, 'r',encoding='utf-8') as f:
        datas = ujson.load(f)
        for data in datas:
            ioc = data["ioc"]
            ioc_type = data["ioc_type"]
            output_data = [ioc, ioc_type]
            output_datas.append(output_data)
        f.close()

    df = pd.DataFrame(data=output_datas)
    df.to_csv(filename, header=False, index=False)


if __name__ == "__main__":
    IOC_file_name = "Query text demo/IOC_text.csv"
    gen_IOC(IOC_file_name)
