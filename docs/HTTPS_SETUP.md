# MORI HTTPS (Let's Encrypt) — 도커 자체완결 · 포트 충돌 없음

이 서버는 **호스트 80·443 을 `lawtoyou_nginx_1`(다른 프로젝트)이 점유**한다. 그래서 MORI 는
**남의 nginx 를 건드리지 않고**, MORI compose 안에서 **빈 포트 18443 에 전용 Caddy** 를 띄워
HTTPS 를 종단한다. 인증서는 `certbot`(도커, DNS-01)로 발급 → Caddy 가 그 파일을 그대로 사용.

결과: `https://mori.example.com:18443` (유효 인증서). GitHub Actions 가 여기로 push 한다.

> host 에 **아무것도 설치하지 않는다**(certbot 도 도커로 실행). lawtoyou nginx 는 손대지 않는다.

---

## STEP 1 — MORI 최신 배포 + 다시 올리기

```bash
cd /opt/mori
git pull origin main
docker compose up -d --build mori-api mori-worker
docker compose ps                                   # mori-api 가 Up(healthy) 인지
curl -s http://127.0.0.1:18000/health && echo "  <-- MORI OK"
```

## STEP 2 — Let's Encrypt 인증서 발급 (도커 certbot · DNS-01)

80/443 을 못 쓰므로 **DNS 인증**을 쓴다(포트 불필요). 대화식으로 TXT 레코드를 알려주면 DNS 에 넣는다.

```bash
sudo docker run -it --rm \
  -v /etc/letsencrypt:/etc/letsencrypt \
  certbot/certbot certonly --manual --preferred-challenges dns \
  -d mori.example.com -m admin@example.com --agree-tos --no-eff-email
```

화면에 이렇게 뜬다 →
```
Please deploy a DNS TXT record under the name:
_acme-challenge.mori.example.com  with the following value:
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```
1. example.com DNS 관리에서 **TXT 레코드** 추가:
   - 이름: `_acme-challenge.mori`  (또는 `_acme-challenge.mori.example.com`)
   - 값: 화면의 `XXXX...` 문자열
2. 1~2분 후 다른 창에서 전파 확인:
   ```bash
   dig +short TXT _acme-challenge.mori.example.com @8.8.8.8
   ```
   값이 보이면 → certbot 화면에서 **Enter**.
3. 성공 시: `/etc/letsencrypt/live/mori.example.com/fullchain.pem` 등 생성. 확인:
   ```bash
   sudo ls -l /etc/letsencrypt/live/mori.example.com/
   ```

## STEP 3 — MORI 전용 Caddy(18443) 기동

`docker-compose.yml` 에 `mori-caddy` 서비스가 이미 있다(git pull 로 받음). 인증서가 생겼으니:

```bash
cd /opt/mori
docker compose up -d mori-caddy
docker compose logs --tail=20 mori-caddy          # 에러 없이 서비스 시작됐는지
```

## STEP 4 — 확인

```bash
curl -sSI https://mori.example.com:18443/health   # HTTP/2 200 + 인증서 검증 통과
```
`SSL certificate problem` 이 없으면 성공. (브라우저로 `https://mori.example.com:18443/ui` 도 확인)

## STEP 5 — GitHub 레포 시크릿을 https 로 (직전 push 실패 해결)

대상 레포 Settings → Secrets and variables → Actions:

- `MORI_INGEST_URL = https://mori.example.com:18443`   ← **스킴 + 포트 포함** (직전 `unknown url type` 원인 해결)
- (유료 Claude 경로면) `ANTHROPIC_API_KEY = <크레딧 있는 키>`

그리고 대상 레포에 **최신 워크플로/스크립트 재복사**(MORI UI 고급 팝업) → 재스캔.

## STEP 6 — 인증서 자동 갱신 (90일)

DNS-01 수동 발급은 자동 갱신이 안 된다. 90일마다 STEP 2 를 다시 하거나, example.com DNS
공급자용 certbot 플러그인(cloudflare/route53 등)이 있으면 아래처럼 자동화:

```bash
# 예: cloudflare — API 토큰을 ~/cf.ini 에 두고
sudo docker run --rm -v /etc/letsencrypt:/etc/letsencrypt -v ~/cf.ini:/cf.ini:ro \
  certbot/dns-cloudflare renew --dns-cloudflare --dns-cloudflare-credentials /cf.ini
docker compose restart mori-caddy
```

---

## (참고) 깔끔한 `:443`(포트 없는 URL) 을 원하면

`lawtoyou_nginx_1` 에 `config/nginx/mori.example.com.conf` 가상호스트를 얹고 그 nginx 에
인증서를 마운트하면 `https://mori.example.com`(포트 없이)로 열 수 있다. 단 **남의 프로젝트
nginx 설정·볼륨을 수정**해야 하므로, 우선은 위 18443 자체완결 방식을 권장한다.
