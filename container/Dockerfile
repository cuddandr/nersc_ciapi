FROM python:3.12-alpine

RUN apk add --no-cache git glab github-cli

ARG CIAPI=/opt/ciapi
RUN git clone https://github.com/cuddandr/nersc_ciapi ${CIAPI}
RUN pip install --no-cache-dir --upgrade -r ${CIAPI}/requirements.txt
ENV APPDIR=${CIAPI}

EXPOSE 8000

# RUN adduser -D -H app
# USER app
WORKDIR ${CIAPI}
CMD ["litestar", "run", "--host", "0.0.0.0"]
