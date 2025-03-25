import http from 'k6/http'
import { check, sleep } from 'k6';

export let options = {
    stages:[
        { duration: '10m', target: 1000 },
        { duration: '5m', target: 0 }
    ]
}

export default function() {
    // const response = http.get("http://host.docker.internal:5055")
    const response = http.get("http://app.service.api/version")
    check(response, {
        "status is 200": (r) => r.status == 200,
        "transaction time OK (200 ms)": (r) => r.timings.duration < 200
    });
    sleep(1);
}

// docker-compose run --rm k6 run /scripts/test.js