import http from 'k6/http'
import { check, sleep } from 'k6';

export let options = {
    vus: 10,
    stages:[
        {target: 1000, duration: '15m'}
    ]
}

export default function() {
    const response = http.get("http://localhost:5219/test")
    check(response, {
        "status is 200": (r) => r.status == 200,
        "transaction time OK": (r) => r.timings.duration < 200
    });
    sleep(1);
}
