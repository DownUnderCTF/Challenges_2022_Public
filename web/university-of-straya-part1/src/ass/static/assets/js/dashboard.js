function clearArticle(articleElem) {
    articleElem.empty();
    $('<div class="close">Close</div>')
        .appendTo(articleElem)
        .on('click', function() {
            location.hash = '';
        });
}

function loadUnits(result) {
    unitDiv = $("div#units-results")
    if (result.length === 0) {
        unitDiv.append("<h3>You are not enrolled in any units!</h3>");
        return
    } else {
        unitDiv.append("<p>Below are the units you have access to!</p>");
    }

    result.forEach(unit => {
        assessmentButton = $("<input></input>").attr({
            class: "primary",
            onclick: `getUnitAssessments(${unit.id}, "${unit.code}");`,
            style: "margin-bottom: 20px; margin-top: 5px",
            type: "submit",
            value: "View Assessments"
        });

        unitDiv.append(
            $("<hr></hr>"),
            $("<h3></h3>").text(`${unit.code} - ${unit.name}`), 
            $("<p></p>").text(unit.description),
            assessmentButton
        );
    });
}

function loadUnitAssessments(result) {
    assessmentArticle = $("article#results");
    
    if (result.length === 0) {
        assessmentArticle.append(
            $("<h3></h3>").text("This unit has no assessments!")
        );
        return
    }

    result.forEach(assessment => {
        goToSubmissionButton = $("<input></input>").attr({
            class: "primary",
            onclick: `getAssessment(${assessment.id});`,
            style: "margin-bottom: 20px; margin-top: 5px",
            type: "submit",
            value: "Go To Assessment"
        });

        assessmentArticle.append(
            $("<hr></hr>"),
            $("<h3></h3>").text(`Assessment: ${assessment.name}`),
            $("<p></p>").text(`Description: ${assessment.description}`),
            $("<p></p>").text(`DEADLINE: ${assessment.deadline}`),
            goToSubmissionButton
        );
    });

    window.location = "#results"
}

function loadSubmissions(result) {
    subDiv = $("div#submissions-results")
    subDiv.empty();

    if (result.length === 0) {
        subDiv.append("<h3>You have not made any submissions!</h3>");
        return
    } else {
        subDiv.append("<p>Below are your submissions.</p>");
    }

    result.forEach(submission => {
        viewButton = $("<input></input>").attr({
            class: "primary",
            onclick: `viewSubmission(${submission.id});`,
            style: "margin-bottom: 20px; margin-top: 5px",
            type: "submit",
            value: "View Submission"
        });

        subDiv.append(
            $("<hr></hr>"),
            $("<h3></h3>").text(submission.name), 
            $("<p></p>").text(`Submitted At: ${submission.submitted}`),
            viewButton
        );
    });
}

function loadAssessments(result) {
    assessmentArticle = $("div#assessments-results");
    assessmentArticle.empty();
    
    if (result.length === 0) {
        assessmentArticle.append(
            $("<h3></h3>").text("This unit has no assessments!")
        );
        return
    }

    result.forEach(assessment => {
        goToSubmissionButton = $("<input></input>").attr({
            class: "primary",
            onclick: `getAssessment(${assessment.id});`,
            style: "margin-bottom: 20px; margin-top: 5px",
            type: "submit",
            value: "Go To Assessment"
        });

        assessmentArticle.append(
            $("<hr></hr>"),
            $("<h3></h3>").text(`Assessment: ${assessment.name}`),
            $("<p></p>").text(`Description: ${assessment.description}`),
            $("<p></p>").text(`DEADLINE: ${assessment.deadline}`),
            goToSubmissionButton
        );
    });
}

function loadAssessment(result) {
    article = $("article#results-alt");

    fileMsg = "Upload a .zip file with your .java code!"

    if (result.submission_type === 'file') {
        fileMsg = "Upload your file for submission!"
    } else if (result.submission_type === 'zip') {
        fileMsg = "Upload a .zip, .tar or .tar.gz file with your assignment!"
    }

    article.append(
        $("<h3></h3>").text(result.name),
        $("<p></p>").text(`DEADLINE: ${result.deadline}`),
        $("<p></p>").text(fileMsg),
        $("<input></input>").attr({
            type: "text",
            style: "margin-bottom: 5px;",
            name: "submission-name", 
            id: "submission-name",
            value: "",
            placeholder: "Name of Your Submission"
        }),
        $("<input></input>").attr({
            type: "file",
            style: "margin-bottom: 5px;",
            name: "submission-file", 
            id: "submission-file",
            value: "",
            placeholder: "Upload File"
        }),
        $("<input></input>").attr({
            class: "primary",
            onclick: `sendSubmission(${result.id});`,
            type: "submit",
            value: "Submit"
        })
    );

    window.location = "#results-alt"
}

function viewSubmission(submissionId) {
    window.location = "#"
    article = $("article#results-alt");
    clearArticle(article);

    // Cbf writing neat code for this
    authAjax({
        url: `/api/assessments/submissions/${submissionId}`,
        type: "GET",
        success: (data) => handleResponse(data, (result) => {
            article.append(
                $("<h2></h2>").text(result.name),
                $("<p></p>").text(`Submitted At: ${result.submitted}`),
                $("<h3></h3>").text("Download Your Submitted Files")
            );
            authAjax({
                url: `/api/assessments/${result.assessment_id}`,
                type: "GET",
                success: (data) => handleResponse(data, (assessment) => {
                    if (assessment.submission_type === "file") {
                        article.append(
                            $("<a></a>").attr({
                                href: `/api/assessments/submissions/${submissionId}/download`
                            }).text("Click to Download Your Submission")
                        );
                    } else {
                        authAjax({
                            url: `/api/assessments/submissions/${submissionId}/files`,
                            method: "GET",
                            success: (data) => handleResponse(data, (subFiles) => {
                                subFiles.forEach(fileName => {
                                    article.append(
                                        $("<a></a>").attr({
                                            href: `/api/assessments/submissions/${submissionId}/download/${fileName}`
                                        }).text(fileName),
                                        $("<br></br>"),
                                        $("<br></br>")
                                    );
                                });
                            }),
                            error: errorCallback
                        })
                    }
                }),
                error: errorCallback
            })
        }),
        error: errorCallback
    });
    window.location = "#results-alt"
}

function sendSubmission(assessmentId) {
    submissionName = $("input#submission-name").val();
    submissionFile = $("input[type=file]#submission-file").prop("files")[0];
    
    reader = new FileReader();
    reader.readAsDataURL(submissionFile);

    reader.onload = () => {
        base64File = reader.result.split(',')[1];
        authAjax({
            url: `/api/assessments/${assessmentId}/submit`,
            type: "POST",
            data: JSON.stringify({name: submissionName, base64_file: base64File}),
            dataType: "json",
            contentType: "application/json",
            success: (data) => handleResponse(data, (result) => {
                successNotify("Your assignment has been submitted!");
                viewSubmission(result.id);
                authAjax({
                    url: "/api/assessments/submissions",
                    type: "GET",
                    success: (data) => handleResponse(data, loadSubmissions),
                    error: errorCallback
                });
            }),
            error: errorCallback
        });
    }

    reader.onerror = (error) => {
        errorNotify(error);
    }
}

function getAssessment(assessmentId) {
    article = $("article#results-alt");
    clearArticle(article);
    authAjax({
        url: `/api/assessments/${assessmentId}`,
        type: "GET",
        success: (data) => handleResponse(data, loadAssessment),
        error: errorCallback
    })
}

function getUnitAssessments(unitId, unitCode) {
    assessmentArticle = $("article#results");
    clearArticle(assessmentArticle);
    
    assessmentArticle.append(
        $("<h2></h2>").text(`${unitCode} - Assessments`)
    )
    authAjax({
        url: `/api/units/${unitId}/assessments`,
        type: "GET",
        success: (data) => handleResponse(data, loadUnitAssessments),
        error: errorCallback
    });
}

$(document).ready(() => {
    authAjax({
        url: "/api/auth/access",
        type: "GET",
        success: (data) => {
            if (data.status === "error") {
                window.location = "/api/auth/logout?redirect=/logout";
            }
        },
        error: errorCallback
    });

    // authAjax({
    //     url: "/api/auth/isstaff",
    //     type: "GET",
    //     success: (data) => {
    //         if (data.status === "success") {
    //             $("ul").append(
    //                 $('<li><a href="/admin">Admin</a></li>')
    //             );
    //         }
    //     },
    //     error: errorCallback
    // });

    setInterval(() => {
        authAjax({
            url: "/api/auth/access",
            type: "GET",
            success: (data) => {
                if (data.status === "error") {
                    window.location = "/api/auth/logout?redirect=/logout";
                }
            },
            error: errorCallback
        });
    }, 60000);

    authAjax({
        url: "/api/units/",
        type: "GET",
        success: (data) => handleResponse(data, loadUnits),
        error: errorCallback
    });

    authAjax({
        url: "/api/assessments/",
        type: "GET",
        success: (data) => handleResponse(data, loadAssessments),
        error: errorCallback
    });

    authAjax({
        url: "/api/assessments/submissions",
        type: "GET",
        success: (data) => handleResponse(data, loadSubmissions),
        error: errorCallback
    });
});