# Purinina sandbox image.
#
# A Kali-based, host-networked pentesting sandbox that ships opencode (pinned)
# plus the purinina opencode configuration (plugin + agents) baked in as the
# *global* opencode config. The model only ever drives opencode from inside
# this container.
#
# Build:  docker build -f docker/Dockerfile -t purinina:latest \
#                       --build-arg OPENCODE_VERSION=1.17.8 .
# (the host launcher does this for you)

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.title="purinina-sandbox" \
      org.opencontainers.image.description="Multi-agent pentesting sandbox (opencode + purinina)" \
      org.opencontainers.image.source="https://github.com/raphaelgpalma/purinina"

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    # Marker the purinina plugin checks before arming offensive tooling.
    PURININA_SANDBOX=1 \
    PURININA_HITL=strict \
    OPENCODE_CONFIG_DIR=/root/.config/opencode

# --- System + pentest tooling (v1 vertical slice: recon + web/exploitation) ---
# Kept deliberately focused; more tools are added as new agents land.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git unzip jq less vim-tiny \
      python3 python3-pip pipx \
      iproute2 net-tools iputils-ping dnsutils \
      openssh-client sshpass \
      nmap masscan \
      whatweb nikto gobuster ffuf wfuzz dirb \
      sqlmap \
      seclists \
      netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

# --- Node.js (for opencode plugin dep install + tooling) ---
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# --- opencode (pinned) ---
ARG OPENCODE_VERSION=1.17.8
ENV OPENCODE_VERSION=${OPENCODE_VERSION}
RUN curl -fsSL https://opencode.ai/install | VERSION="${OPENCODE_VERSION}" bash \
    && ln -sf /root/.opencode/bin/opencode /usr/local/bin/opencode \
    && opencode --version

# --- Purinina opencode configuration (baked as GLOBAL config) ---
# Directory layout mirrors what opencode auto-loads from ~/.config/opencode:
#   opencode.json  -> providers / agents / permissions / plugin registration
#   plugin/        -> the purinina plugin (HITL policy, sandbox guard, tools)
#   agent/         -> agent personas (orchestrator + specialists)
RUN mkdir -p ${OPENCODE_CONFIG_DIR}/plugin ${OPENCODE_CONFIG_DIR}/agent
COPY runtime/opencode.json ${OPENCODE_CONFIG_DIR}/opencode.json
# Only the plugin source itself goes into the plugin dir — opencode treats every
# file there as a plugin, so package.json/tsconfig must NOT be copied here.
COPY runtime/plugin/purinina.ts ${OPENCODE_CONFIG_DIR}/plugin/purinina.ts
COPY runtime/agent/ ${OPENCODE_CONFIG_DIR}/agent/

# Pre-install plugin runtime dependencies so the first launch is fast and
# fully offline-reproducible (no bun install on first session).
COPY runtime/plugin/package.json ${OPENCODE_CONFIG_DIR}/package.json
RUN cd ${OPENCODE_CONFIG_DIR} && npm install --no-audit --no-fund --omit=dev

# --- Ready-made engagement workspace skeleton (CAI-style folder structure) ---
# Copied to a template location; the entrypoint seeds the mounted workspace
# from this template if the workspace is empty.
COPY runtime/workspace-skeleton/ /opt/purinina/workspace-skeleton/

# --- Entrypoint ---
COPY docker/entrypoint.sh /usr/local/bin/purinina-entrypoint
RUN chmod +x /usr/local/bin/purinina-entrypoint

WORKDIR /root/engagement
ENTRYPOINT ["/usr/local/bin/purinina-entrypoint"]
# Default: stay alive so the host launcher can `docker exec` opencode into it.
CMD ["sleep", "infinity"]
