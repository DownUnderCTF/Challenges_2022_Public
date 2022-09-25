function createAssignment() {
    assName = $("input#assessments-name").val();
    assDesc = $("input#assessments-desc").val();
    assUnit = $("select#assessment-units").val();
    assType = $("select#assessment-type").val();
    assMarks = $("input#assessments-marks").val();
    assDate = Math.floor(new Date($("input#assessments-deadline").val()).getTime()/1000);

    try {
        assMarks = parseInt(assMarks);
    } catch (err) {
        errorNotify("Marks needs to be an integer!");
        return
    }

    authAjax({
        url: `/api/units/${assUnit}/addassessment`,
        type: "POST",
        data: JSON.stringify({
            name: assName,
            description: assDesc,
            submission_type: assType,
            total_marks: assMarks,
            deadline_epoch: assDate
        }),
        dataType: "json",
        contentType: "application/json",
        success: (data) => handleResponse(data, (result) => successNotify("Assignment has been created!")),
        error: errorCallback
    });
}

function enrolStudent() {
    studentId = parseInt($("select#students-students").val());
    unitId = $("select#students-units").val();

    authAjax({
        url: `/api/units/${unitId}/addstudent`,
        type: "POST",
        data: JSON.stringify({
            student_id: studentId
        }),
        dataType: "json",
        contentType: "application/json",
        success: (data) => handleResponse(data, (result) => successNotify("Student has been enrolled into the unit!")),
        error: errorCallback
    });
}

function loadUnits(units) {
    selectElem = $("select#assessment-units");
    studentsElem = $("select#students-units");
    units.forEach(unit => {
        unitOpt = $("<option></option>").attr({
            value: unit.id
        }).text(unit.code);
        selectElem.append(unitOpt);
        unitOpt = $("<option></option>").attr({
            value: unit.id
        }).text(unit.code);
        studentsElem.append(unitOpt);
    });
}

function loadStudents(students) {
    selectElem = $("select#students-students");
    students.forEach(student => {
        studentOpt = $("<option></option>").attr({
            value: student.id
        }).text(student.username);
        selectElem.append(studentOpt);
    });
}

$(document).ready(() => {
    authAjax({
        url: "/api/auth/isstaff",
        type: "GET",
        success: (data) => {
            if (data.status === "success") {
                successNotify(data.result);
            } else {
                window.location = "/dashboard"
            }
        },
        error: errorCallback
    });

    setInterval(() => {
        authAjax({
            url: "/api/auth/isstaff",
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
        url: "/api/users/",
        type: "GET",
        success: (data) => handleResponse(data, loadStudents),
        error: errorCallback
    });

    authAjax({
        url: "/api/units/",
        type: "GET",
        success: (data) => handleResponse(data, loadUnits),
        error: errorCallback
    });
});