FROM docker.elastic.co/elasticsearch/elasticsearch:8.10.4

# 한국어 형태소 분석기 nori 설치
RUN ./bin/elasticsearch-plugin install analysis-nori

# ElasticSearch 설정 파일 복사
COPY ./config/elasticsearch.yml /usr/share/elasticsearch/config/elasticsearch.yml

# 타임존 설정
ENV TZ=Asia/Seoul

# 권한 설정
USER root
RUN chown -R elasticsearch:elasticsearch /usr/share/elasticsearch/config/
USER elasticsearch

# 볼륨 설정
VOLUME ["/usr/share/elasticsearch/data"]

# 포트 설정
EXPOSE 9200 9300