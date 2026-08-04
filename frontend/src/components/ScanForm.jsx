import { useState } from "react";
import axios from "axios";

function ScanForm() {
    const [url, setUrl] = useState("");
    const [result, setResult] = useState(null);

    const handleSubmit = async (e) => {
        e.preventDefault();

        try {
            const response = await axios.get(
                `http://127.0.0.1:8000/headers/${url}`
            );

            console.log(response.data);
            setResult(response.data);

        } catch (error) {
            console.error(error);
        }
    };

    return (
        <>
            <form onSubmit={handleSubmit} className="scan-form">

                <input
                    type="text"
                    placeholder="Enter website (example.com)"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                />

                <button type="submit">
                    Scan Website
                </button>

            </form>

            {result && (
                <div className="results">

                    <h2>Scan Result</h2>

                    <p>
                        <strong>URL:</strong> {result.url}
                    </p>

                    <p>
                        <strong>Security Score:</strong> {result.security_score}/100
                    </p>

                    <p>
                        <strong>Grade:</strong> {result.grade}
                    </p>

                    <p>
                        <strong>Overall Risk:</strong> {result.overall_risk}
                    </p>

                    <h3>Security Headers</h3>

                    {Object.entries(result.security_headers).map(
                        ([header, info]) => (
                            <div key={header} className="header-card">

                                <h4>{header}</h4>

                                <p>
                                    <strong>Status:</strong> {info.status}
                                </p>

                                <p>
                                    <strong>Risk:</strong> {info.risk}
                                </p>

                                {info.value && (
                                    <p>
                                        <strong>Value:</strong> {info.value}
                                    </p>
                                )}

                                {info.recommendation && (
                                    <p>
                                        <strong>Recommendation:</strong>{" "}
                                        {info.recommendation}
                                    </p>
                                )}

                            </div>
                        )
                    )}

                </div>
            )}
        </>
    );
}

export default ScanForm;