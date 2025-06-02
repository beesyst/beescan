FROM postgres:17.5

ENV POSTGRES_USER=secweb_user
ENV POSTGRES_PASSWORD=secweb_pass
ENV POSTGRES_DB=beescan

COPY init.sql /docker-entrypoint-initdb.d/
