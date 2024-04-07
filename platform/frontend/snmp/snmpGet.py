from flask import Flask, request, jsonify
from pysnmp.hlapi import *

app = Flask(__name__)

def snmp_get(oid, target_ip, community='public', port=161):
    """
    Perform an SNMP GET operation.
    """
    iterator = getCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((target_ip, port)),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )

    error_indication, error_status, error_index, var_binds = next(iterator)
    if error_indication:
        return str(error_indication)
    elif error_status:
        return '%s at %s' % (
            error_status.prettyPrint(),
            error_index and var_binds[int(error_index) - 1][0] or '?'
        )
    else:
        for var_bind in var_binds:
            return str(var_bind[1])

@app.route('/api/snmp', methods=['POST'])
def handle_snmp_request():
    """
    Handle SNMP GET requests via HTTP POST.
    """
    data = request.json
    oid = data.get('oid')
    ip = data.get('ip')
    community = data.get('community', 'public')
    result = snmp_get(oid, ip, community)
    if result is not None:
        return jsonify({'success': True, 'data': result}), 200
    else:
        return jsonify({'success': False, 'error': 'Unable to fetch OID value'}), 500

if __name__ == '__main__':
    app.run(debug=True)
