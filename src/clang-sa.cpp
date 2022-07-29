#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"

using namespace clang;
using namespace clang::ento;

namespace {
class MyChecker final : public Checker<check::PreStmt<UnaryOperator>,
		check::Bind, check::Location> {
  //mutable std::unique_ptr<BugType> BT;

  const BugType BT{this, "je 3", categories::LogicError};

public:
  void checkBind(const SVal &loc, const SVal &val, const Stmt *S,
		 CheckerContext &C) const;
  void checkPreStmt(const UnaryOperator *UO, CheckerContext &C) const;
  void checkLocation(const SVal &loc, bool isLoad, const Stmt *S,
		     CheckerContext &C) const;
};
}

REGISTER_MAP_WITH_PROGRAMSTATE(Changed, SymbolRef, int);

class MyVisitor final : public BugReporterVisitor {
public:
    MyVisitor(SymbolRef Sym) : Sym(Sym) {}
  virtual PathDiagnosticPieceRef VisitNode(const ExplodedNode *N,
					   BugReporterContext &BRC,
					   PathSensitiveBugReport &BR) override {
		/*if (N->getLocation().getKind() != ProgramPoint::PostStoreKind)
			return nullptr;*/

		auto state = N->getState();
		auto ch = state->get<Changed>(Sym);
		if (!ch)
			return nullptr;

		//llvm::errs() << __func__ << " BR=" << &BR << " loc=";
#ifdef DUMP_LOC
		N->getLocation().dump();
		llvm::errs() << "\n";
#endif
#ifdef DUMP_STATE
		N->getState()->dump();
		llvm::errs() << "\n";
#endif
		if (*ch != 2) {
			//llvm::errs() << "\tIGN due CUR ch=" << *ch << "\n";
			return nullptr;
		}

		state = N->getFirstPred()->getState();
		ch = state->get<Changed>(Sym);
		if (!ch || *ch == 2) {
			//llvm::errs() << "\tIGN due PRED ch=" << *ch << "\n";
			return nullptr;
		}

		//llvm::errs() << "\tTAKING\n";

		const auto S = N->getStmtForDiagnostics();
		if (!S)
		  return nullptr;

		auto NCtx = N->getLocationContext();
		auto L = PathDiagnosticLocation::createBegin(S, BRC.getSourceManager(), NCtx);
		if (!L.isValid() || !L.asLocation().isValid())
		  return nullptr;
		llvm::errs() << "L=";
		L.dump();
		return std::make_shared<PathDiagnosticEventPiece>(L, "Originated here");
	}
	virtual void Profile(llvm::FoldingSetNodeID &ID) const override {
	    static int X = 0;
	    ID.AddPointer(&X);
	    ID.Add(Sym);
	}
private:
    SymbolRef Sym;
};

void MyChecker::checkBind(const SVal &loc, const SVal &val, const Stmt *S,
			  CheckerContext &C) const
{
	auto state = C.getState();

#ifdef BIND_DEBUG
	llvm::errs() << __func__ << "\n";
	S->dumpColor();
	llvm::errs() << "loc=";
	loc.dump();
	llvm::errs() << " locreg=";
	loc.getAsRegion()->dump();
	llvm::errs() << " val=";
	val.dump();
	llvm::errs() << "\n";
#endif

	auto intVal = val.getAs<nonloc::ConcreteInt>();
	if (!intVal) {
	    llvm::errs() << "\tNOTINT\n";
		return;
	}

	//llvm::errs() << "\tintVal=" << intVal->getValue().getExtValue() << "\n";

	C.addTransition(state->set<Changed>(loc.getAsLocSymbol(), intVal->getValue().getExtValue()));

#ifdef DUMP_STATE
	state->dump();
	llvm::errs() << "\n";
#endif

	if (val.isConstant(3)) {
		//auto &BR = C.getBugReporter();
		auto N = C.generateNonFatalErrorNode();
		if (!N)
			return;
		auto B = std::make_unique<PathSensitiveBugReport>(BT,
								  BT.getDescription(),
								  N);
		B->addRange(S->getSourceRange());
		B->addVisitor<MyVisitor>(loc.getAsLocSymbol());
		C.emitReport(std::move(B));
		/*BR.EmitBasicReport(nullptr, this, "vic jak 3",
				   categories::LogicError, "tu",
				   PathDiagnosticLocation(S,
							  C.getSourceManager(),
							  C.getLocationContext()));*/
		//C.addSink();
	}
}

void MyChecker::checkPreStmt(const UnaryOperator *UO,
			     CheckerContext &C) const
{
	return;
	llvm::errs() << __func__ << "\n";
	UO->dumpColor();
	auto E = UO->getSubExpr();
	auto SVal = C.getSVal(E);
	SVal.dump();
	llvm::errs() << "\n";
}

void MyChecker::checkLocation(const SVal &loc, bool isLoad, const Stmt *S,
			      CheckerContext &C) const
{
	return;
	llvm::errs() << __func__ << "\n";
	S->dumpColor();
	llvm::errs() << "isLoad=" << isLoad << " loc=";
	loc.dump();
	llvm::errs() << " locreg=";
	loc.getAsRegion()->dump();
	llvm::errs() << "\n";
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<MyChecker>("example.MyChecker",
				 "Disallows calls to functions called main",
				 "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
		CLANG_ANALYZER_API_VERSION_STRING;
