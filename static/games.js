// Mini crossword and Sudoku for the Games page

// ---------- Crossword ----------

// "." marks a blocked square
const CROSSWORD = [
    "HOPE",
    "E..A",
    "A..S",
    "LOVE",
];

const CLUES = {
    across: [
        [1, "Feeling that things will get better"],
        [3, "Strong affection and care for someone"],
    ],
    down: [
        [1, "Recover, as a wound or a broken heart"],
        [2, "Freedom from worry or discomfort"],
    ],
};

// Clue numbers shown in the corner of the starting square
const NUMBERS = { "0,0": 1, "0,3": 2, "3,0": 3 };

function buildCrossword() {
    const grid = document.getElementById("crossword");
    grid.style.gridTemplateColumns = `repeat(${CROSSWORD[0].length}, 1fr)`;

    CROSSWORD.forEach((row, r) => {
        [...row].forEach((letter, c) => {
            const cell = document.createElement("div");
            cell.className = "cell";

            if (letter === ".") {
                cell.classList.add("blocked");
            } else {
                const number = NUMBERS[`${r},${c}`];
                if (number) {
                    const label = document.createElement("span");
                    label.className = "cell-number";
                    label.textContent = number;
                    cell.appendChild(label);
                }
                const input = document.createElement("input");
                input.maxLength = 1;
                input.dataset.answer = letter;
                input.setAttribute("aria-label", `Row ${r + 1}, column ${c + 1}`);
                input.addEventListener("input", () => {
                    input.value = input.value.replace(/[^a-z]/gi, "").toUpperCase();
                    input.classList.remove("wrong", "right");
                });
                cell.appendChild(input);
            }
            grid.appendChild(cell);
        });
    });

    for (const direction of ["across", "down"]) {
        const list = document.getElementById(`clues-${direction}`);
        for (const [number, clue] of CLUES[direction]) {
            const item = document.createElement("li");
            item.innerHTML = `<strong>${number}.</strong> ${clue}`;
            list.appendChild(item);
        }
    }
}

function crosswordInputs() {
    return document.querySelectorAll("#crossword input");
}

function checkCrossword() {
    let correct = 0;
    const inputs = crosswordInputs();
    inputs.forEach((input) => {
        input.classList.remove("wrong", "right");
        if (!input.value) return;
        const ok = input.value === input.dataset.answer;
        input.classList.add(ok ? "right" : "wrong");
        if (ok) correct++;
    });
    document.getElementById("crossword-message").textContent =
        correct === inputs.length
            ? "You solved it! 🎉"
            : `${correct} of ${inputs.length} letters correct. Keep going!`;
}

function revealCrossword() {
    crosswordInputs().forEach((input) => {
        input.value = input.dataset.answer;
        input.classList.remove("wrong", "right");
    });
    document.getElementById("crossword-message").textContent = "";
}

function clearCrossword() {
    crosswordInputs().forEach((input) => {
        input.value = "";
        input.classList.remove("wrong", "right");
    });
    document.getElementById("crossword-message").textContent = "";
}

// ---------- Sudoku ----------

const EMPTY_CELLS = 45;

function shuffle(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}

// Build a random valid solved board by shuffling a base pattern
function generateSolution() {
    const digits = shuffle([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    const order = () => shuffle([0, 1, 2]).flatMap((band) => shuffle([0, 1, 2]).map((i) => band * 3 + i));
    const rows = order();
    const cols = order();
    return rows.map((r) => cols.map((c) => digits[(r * 3 + Math.floor(r / 3) + c) % 9]));
}

function newSudoku() {
    const grid = document.getElementById("sudoku");
    grid.innerHTML = "";
    document.getElementById("sudoku-message").textContent = "";

    const solution = generateSolution();
    const hidden = new Set(shuffle([...Array(81).keys()]).slice(0, EMPTY_CELLS));

    for (let i = 0; i < 81; i++) {
        const r = Math.floor(i / 9);
        const c = i % 9;
        const cell = document.createElement("div");
        cell.className = "cell";
        if (c % 3 === 2 && c !== 8) cell.classList.add("box-right");
        if (r % 3 === 2 && r !== 8) cell.classList.add("box-bottom");

        const input = document.createElement("input");
        input.maxLength = 1;
        input.inputMode = "numeric";
        input.setAttribute("aria-label", `Row ${r + 1}, column ${c + 1}`);
        if (hidden.has(i)) {
            input.addEventListener("input", () => {
                input.value = input.value.replace(/[^1-9]/g, "");
                input.classList.remove("wrong");
            });
        } else {
            input.value = solution[r][c];
            input.readOnly = true;
            input.classList.add("given");
        }
        cell.appendChild(input);
        grid.appendChild(cell);
    }
}

// Check the board against Sudoku rules (any valid completion counts)
function checkSudoku() {
    const inputs = [...document.querySelectorAll("#sudoku input")];
    const values = inputs.map((input) => input.value);
    inputs.forEach((input) => input.classList.remove("wrong"));

    let conflicts = false;
    values.forEach((value, i) => {
        if (!value) return;
        const r = Math.floor(i / 9);
        const c = i % 9;
        const clash = values.some((other, j) => {
            if (j === i || other !== value) return false;
            const r2 = Math.floor(j / 9);
            const c2 = j % 9;
            const sameBox = Math.floor(r / 3) === Math.floor(r2 / 3) && Math.floor(c / 3) === Math.floor(c2 / 3);
            return r === r2 || c === c2 || sameBox;
        });
        if (clash && !inputs[i].readOnly) {
            inputs[i].classList.add("wrong");
            conflicts = true;
        }
    });

    const message = document.getElementById("sudoku-message");
    if (conflicts) {
        message.textContent = "Some numbers clash. Check the highlighted cells.";
    } else if (values.includes("")) {
        message.textContent = "No mistakes so far. Keep going!";
    } else {
        message.textContent = "You solved it! 🎉";
    }
}

// ---------- Setup ----------

document.addEventListener("DOMContentLoaded", () => {
    buildCrossword();
    document.getElementById("crossword-check").addEventListener("click", checkCrossword);
    document.getElementById("crossword-reveal").addEventListener("click", revealCrossword);
    document.getElementById("crossword-clear").addEventListener("click", clearCrossword);

    newSudoku();
    document.getElementById("sudoku-check").addEventListener("click", checkSudoku);
    document.getElementById("sudoku-new").addEventListener("click", newSudoku);
});
