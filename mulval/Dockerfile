FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    swi-prolog graphviz make gcc g++ \
    && rm -rf /var/lib/apt/lists/*

# MulVAL would be installed here from source
# For now this is a placeholder — the Python fallback handles analysis
WORKDIR /opt/mulval

COPY run_mulval.sh /opt/mulval/run_mulval.sh
COPY rules/ /opt/mulval/rules/
RUN chmod +x /opt/mulval/run_mulval.sh

ENTRYPOINT ["/opt/mulval/run_mulval.sh"]
