// Tracks asynchronous backup reissue work so stale completions cannot commit UI state.
class ReprotectWork {
  constructor() {
    this.generation = 0;
  }

  begin() {
    this.generation += 1;
    return this.generation;
  }

  beginAndClear(fields) {
    const values = fields.map((field) => field.value);
    const generation = this.begin();
    fields.forEach((field) => { field.value = ''; });
    return { generation, values };
  }

  isCurrent(generation) {
    return generation === this.generation;
  }
}

if (typeof module !== 'undefined' && module.exports) module.exports = ReprotectWork;
if (typeof window !== 'undefined') window.ReprotectWork = ReprotectWork;
