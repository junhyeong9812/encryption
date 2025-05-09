FROM postgres:16-alpine

# 로케일 설정 (한글 지원)
RUN apk add --no-cache icu-libs tzdata
ENV LANG=ko_KR.utf8
ENV TZ=Asia/Seoul

# PostgreSQL 추가 확장 모듈 설치
RUN apk add --no-cache --virtual .build-deps gcc musl-dev make \
    && apk add --no-cache postgresql-contrib \
    && apk del .build-deps

# 초기화 스크립트 디렉토리 생성
RUN mkdir -p /docker-entrypoint-initdb.d

# 초기화 스크립트 복사
COPY ./init-scripts/ /docker-entrypoint-initdb.d/

# PostgreSQL 설정 강화 (선택적)
# RUN echo "shared_buffers = 256MB" >> /usr/local/share/postgresql/postgresql.conf.sample
# RUN echo "max_connections = 100" >> /usr/local/share/postgresql/postgresql.conf.sample
# RUN echo "effective_cache_size = 1GB" >> /usr/local/share/postgresql/postgresql.conf.sample

# 볼륨 설정
VOLUME ["/var/lib/postgresql/data"]

# 포트 설정
EXPOSE 5432

# 관리자 명령 실행 권한 부여
RUN chmod +x /docker-entrypoint-initdb.d/*.sql || true