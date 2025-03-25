import http from 'k6/http'
import { check, sleep } from 'k6';

export let options = {
    stages:[
        { duration: '10m', target: 200 },
        { duration: '5m', target: 0 }
    ]
}

export default function() {
    const url = 'http://app.service.api/login';
    const payload = JSON.stringify({
        email: 'test@mail.com',
        password: '1234',
    });

    const params = {
        headers: {
            'Content-Type': 'application/json',
        },
    };
    
    const response = http.post(url, payload, params);
    check(response, {
        "status = 200": (r) => r.status == 200,
        "transaction time OK": (r) => r.timings.duration < 200
    });
    sleep(1);
}
