FROM python:3.12-alpine

WORKDIR /app
COPY vpn_exporter.py .

EXPOSE 9090

ENTRYPOINT ["python3", "vpn_exporter.py"]
CMD ["--socket", "/var/run/vpn.sock", "--port", "9090"]
