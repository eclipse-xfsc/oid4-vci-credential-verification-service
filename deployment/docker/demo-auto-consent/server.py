import json
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)


def extract_disclosures(dcql_query, query_id):
    """
    Extract requested claim paths for a given DCQL credential query.

    Currently supports top-level SD-JWT claims.
    """
    if not isinstance(dcql_query, dict):
        return []

    credentials = dcql_query.get('credentials', [])

    if not isinstance(credentials, list):
        return []

    for credential in credentials:
        if not isinstance(credential, dict):
            continue

        if credential.get('id') != query_id:
            continue

        disclosures = []

        for claim in credential.get('claims', []):
            if not isinstance(claim, dict):
                continue

            path = claim.get('path', [])

            if not isinstance(path, list) or not path:
                continue

            # Current signer expects top-level claim names.
            if len(path) == 1 and isinstance(path[0], str):
                disclosures.append(path[0])

        return list(dict.fromkeys(disclosures))

    return []


class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == '/health':
            self.respond(200, {'status': 'ok'})
        else:
            self.respond(404, {'error': 'not found'})

    def do_POST(self):
        if self.path not in ('/', '/policy', '/evaluate'):
            return self.respond(404, {'error': 'not found'})

        try:
            size = int(self.headers.get('Content-Length', '0'))

            if size <= 0 or size > 1024 * 1024:
                return self.respond(400, {
                    'error': 'invalid body length'
                })

            body = json.loads(self.rfile.read(size))

            if not isinstance(body, dict):
                return self.respond(400, {
                    'error': 'JSON object required'
                })

            credentials = body.get('credentials')

            if not isinstance(credentials, list):
                return self.respond(400, {
                    'error': 'credentials array required'
                })

            dcql_query = body.get('dcqlQuery', {})

            selections = []

            for item in credentials:
                if not isinstance(item, dict):
                    return self.respond(400, {
                        'error': 'invalid credential entry'
                    })

                query_id = item.get('queryId')
                credential_id = item.get('credentialId')

                if (
                    not isinstance(query_id, str)
                    or not query_id
                    or not isinstance(credential_id, str)
                    or not credential_id
                ):
                    return self.respond(400, {
                        'error': 'queryId and credentialId must be nonempty strings'
                    })

                disclosures = extract_disclosures(
                    dcql_query,
                    query_id
                )

                selection = {
                    'queryId': query_id,
                    'credentialId': credential_id,
                    'disclosures': disclosures
                }

                selections.append(selection)

                logging.info(
                    'Selected credential: queryId=%s credentialId=%s disclosures=%s',
                    query_id,
                    credential_id,
                    disclosures
                )

            logging.info(
                'Approved %d credential selections',
                len(selections)
            )

            self.respond(200, {
                'approved': True,
                'selections': selections
            })

        except (ValueError, UnicodeDecodeError) as exc:
            self.respond(400, {'error': str(exc)})

    def respond(self, code, data):
        payload = json.dumps(data).encode('utf-8')

        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()

        self.wfile.write(payload)


if __name__ == '__main__':
    port = int(os.getenv('PORT', '8080'))

    logging.info(
        'Starting XFSC credential selection policy on port %d',
        port
    )

    ThreadingHTTPServer(
        ('0.0.0.0', port),
        Handler
    ).serve_forever()