import http from 'k6/http'
import { check, sleep } from 'k6';

export let options = {
    vus: 50,
    stages:[
        {target: 100, duration: '2m'},
        {target: 100, duration: '1m'},
        {target: 10, duration: '20s'},
    ]
}

export default function() {
    // const response = http.get("http://host.docker.internal:5055")
    const response = http.get("http://host.docker.internal/version")
    check(response, {
        "status is 200": (r) => r.status == 200,
        "transaction time OK (200 ms)": (r) => r.timings.duration < 200
    });
    sleep(1);
}

// docker-compose run --rm k6 run /scripts/test.js